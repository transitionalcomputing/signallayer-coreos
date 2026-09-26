#!/usr/bin/env bash
# Run on native x86_64 Linux with rootful Podman; never starts a VM.
set -Eeuo pipefail

build_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
builder='ghcr.io/osbuild/image-builder-cli@sha256:adde8da071d78b17db2e6bb2df1aab4e01dd141efe7b7f9f68d5b51e590502d5'
source_ref=${1:-localhost/signallayer-coreos:0.0.2}
if (( $# > 1 )); then
    echo "Usage: $0 [local CoreOS OCI reference]" >&2
    exit 2
fi
mkdir -p "$build_dir/output"
run_dir=$(mktemp -d "$build_dir/output/coreos-0.0.2-x86_64.XXXXXXXX")
trap 'result=$?; if (( result != 0 )); then echo "Disk build failed (exit $result); see $run_dir/build-report.txt"; fi' EXIT
main() {
    printf 'Builder: %s\nSource reference: %s\nHost: %s\n' "$builder" "$source_ref" "$(uname -sm)"

    if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
        echo 'Requires native x86_64 Linux (for example Fedora 44), rootful Podman, loop devices and privileged filesystem mounts. macOS/arm64 emulation is not supported by this entry point.'
        exit 1
    fi
    if (( EUID != 0 )); then
        echo 'Run with sudo; the source image must be in rootful Podman storage.'
        exit 1
    fi
    for tool in podman qemu-img sha256sum python3 losetup lsblk sfdisk mount umount file cmp findmnt debugfs; do
        command -v "$tool" >/dev/null || { echo "Missing required tool: $tool"; exit 1; }
    done
    [[ $(podman info --format '{{.Host.Arch}}') == amd64 ]] || { echo 'Podman must use native amd64 Linux.'; exit 1; }
    source_id=$(podman image inspect "$source_ref" --format '{{.Id}}')
    podman image inspect "$source_id" > "$run_dir/source-image.json"
    [[ $(podman image inspect "$source_id" --format '{{.Os}}/{{.Architecture}}') == linux/amd64 ]] || { echo 'Source must be linux/amd64.'; exit 1; }
    [[ $(podman image inspect "$source_id" --format '{{index .Labels "containers.bootc"}}') == 1 ]] || { echo 'Source must be a bootc image.'; exit 1; }
    [[ $(podman image inspect "$source_id" --format '{{index .Labels "org.opencontainers.image.version"}}') == 0.0.2 ]] || { echo 'Source must be CoreOS 0.0.2.'; exit 1; }
    [[ $(podman image inspect "$source_id" --format '{{index .Labels "org.opencontainers.image.title"}}') == 'SignalLayerIT CoreOS' ]] || { echo 'Source must be SignalLayerIT CoreOS.'; exit 1; }
    printf 'Immutable local source ID: %s\n' "$source_id"

    # Export by immutable ID. The tool container gets its own disposable Podman
    # store, rather than sharing or modifying the host store.
    podman save --format oci-archive --output "$run_dir/source.oci.tar" "$source_id"
    cp "$build_dir/qcow2.toml" "$run_dir/qcow2.toml"
    sha256sum "$run_dir/source.oci.tar" "$run_dir/qcow2.toml"
    podman pull --arch amd64 "$builder"
    podman run --rm --privileged --security-opt label=disable \
        --volume "$run_dir:/output" \
        --volume "$build_dir/prepare-boot-manifest.py:/prepare-boot-manifest.py:ro" \
        --entrypoint /bin/bash "$builder" \
        -Eeuo pipefail -c '
        expected_id=$1
        image-builder version --format=json | tee /output/builder-version.json
        podman load --input /output/source.oci.tar
        podman tag "$expected_id" localhost/signallayer-coreos:0.0.2
        actual_id=$(podman image inspect localhost/signallayer-coreos:0.0.2 --format "{{.Id}}")
        [[ ${actual_id#sha256:} == ${expected_id#sha256:} ]]
        printf "Builder payload local ID: %s\n" "$actual_id"
        podman run --rm --entrypoint /usr/bin/bootc localhost/signallayer-coreos:0.0.2 container lint
        podman run --rm --entrypoint /bin/cat localhost/signallayer-coreos:0.0.2 /usr/lib/signallayer/release > /output/source-release
        podman run --rm --entrypoint /bin/cat localhost/signallayer-coreos:0.0.2 /usr/lib/ostree/prepare-root.conf > /output/source-prepare-root.conf
        image-builder bootc inspect --ref localhost/signallayer-coreos:0.0.2 --format=json > /output/bootc-inspect.json
        podman run --rm --entrypoint /usr/sbin/matchpathcon localhost/signallayer-coreos:0.0.2 \
            -n -m dir /ostree > /output/source-ostree-context
        if [[ $(cat /output/source-ostree-context) == system_u:object_r:usr_t:s0 ]]; then
            # Retain the original path for pre-hardening baseline images.
            image-builder build --bootc-ref localhost/signallayer-coreos:0.0.2 \
                --arch x86_64 --bootc-default-fs ext4 --blueprint /output/qcow2.toml \
                --output-dir /output --output-name signallayer-coreos-0.0.2-x86_64 \
                --seed 1 --with-manifest --with-buildlog qcow2
        else
            image-builder manifest --bootc-ref localhost/signallayer-coreos:0.0.2 \
            --arch x86_64 --bootc-default-fs ext4 --blueprint /output/qcow2.toml \
            --seed 1 qcow2 > /output/image-builder-manifest.json
            python3 /prepare-boot-manifest.py /output/image-builder-manifest.json \
            /output/source-ostree-context /output/signallayer-coreos-0.0.2-x86_64.osbuild-manifest.json
            # Match the pinned CLI pkg/setup.EnsureEnvironment before invoking
            # OSBuild directly: its volume supports xattrs, and install_t can
            # write image contexts unknown to the host without loading policy.
            store=/var/cache/image-builder/store
            mkdir -p "$store"
            chcon system_u:object_r:root_t:s0 "$store"
            mkdir -p /run/osbuild
            mountpoint -q /run/osbuild || mount -t tmpfs tmpfs /run/osbuild
            cp -p /usr/bin/osbuild /run/osbuild/osbuild
            chcon system_u:object_r:install_exec_t:s0 /run/osbuild/osbuild
            mount -t devtmpfs devtmpfs /dev
            mount --bind /run/osbuild/osbuild /usr/bin/osbuild
            osbuild --store "$store" --cache-max-size=21474836480 \
            --export qcow2 --output-directory /output/osbuild \
            /output/signallayer-coreos-0.0.2-x86_64.osbuild-manifest.json \
            2>&1 | tee /output/signallayer-coreos-0.0.2-x86_64.buildlog
            mv /output/osbuild/qcow2/disk.qcow2 /output/signallayer-coreos-0.0.2-x86_64.qcow2
        fi
        ' build-qcow2 "$source_id"

    disk="$run_dir/signallayer-coreos-0.0.2-x86_64.qcow2"
    [[ -s $disk ]]
    bash "$build_dir/inspect-qcow2.sh" "$disk"
    sha256sum "$disk"
    printf 'Disk constructed and inspected: %s\nDisk has not been booted.\n' "$disk"
}
main 2>&1 | tee "$run_dir/build-report.txt"
