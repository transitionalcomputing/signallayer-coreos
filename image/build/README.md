# CoreOS 0.0.1 development disk

Run from the repository root on **native x86_64 Linux**, for example Fedora 44.
Requirements: rootful Podman, Bash, Python 3, `qemu-img`, `file`, coreutils,
util-linux (`losetup`, `lsblk`, `sfdisk`, `mount`), usable loop devices, and
permission to run privileged containers and mount filesystems. Allow at least
20 GiB free space for the OCI archive, temporary container storage and disk;
offline inspection also creates a sparse 32 GiB raw copy. This entry point
does not support macOS/arm64 or experimental cross-architecture builds.

The maintained unified builder is pinned to its linux/amd64 manifest:

```text
ghcr.io/osbuild/image-builder-cli@sha256:adde8da071d78b17db2e6bb2df1aab4e01dd141efe7b7f9f68d5b51e590502d5
image-builder 83.0.0
commit 50cdd3fbc2940f5ddf877dfd9033423c9ce6e1ca
osbuild 194
```

Its installed `build --help` supplies the flags used here. See upstream
[installation](https://osbuild.org/docs/developer-guide/projects/image-builder/installation/)
and [bootc usage](https://osbuild.org/docs/developer-guide/projects/image-builder/usage/#bootc).
The deprecated standalone CLI is not used.

Build the OCI image from the current Containerfile into **rootful** storage:

```bash
sudo podman build --platform linux/amd64 \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg BUILD_ID="0.0.1-$(git rev-parse --short=12 HEAD)-local" \
  -f Containerfile -t localhost/signallayer-coreos:0.0.1 .
sudo bash image/build/build-qcow2.sh
```

Alternatively, transfer the existing Phase 1 Docker image without rebuilding:
on its Docker host run:

```bash
docker image inspect localhost/signallayer-coreos:0.0.1
docker save -o /tmp/coreos-0.0.1.tar localhost/signallayer-coreos:0.0.1
```

Copy that archive to the Linux host, then run
`sudo podman load -i /tmp/coreos-0.0.1.tar`. Record the original Docker
image identity with `docker image inspect`; Docker's index ID and Podman's
configuration ID can differ. The wrapper records the native Podman identity
actually used, exports by immutable ID, and verifies that ID after loading
into the builder's disposable store. It never shares the host storage with
the nested Podman instance.

Each run creates an ignored directory under `image/build/output/` containing
`signallayer-coreos-0.0.1-x86_64.qcow2`, the input OCI archive, copied blueprint,
source image inspection and release/configuration, builder version, OSBuild
manifest/log, checksums in `build-report.txt`, and offline inspection reports.
For Phase 3B images, `prepare-boot-manifest.py` adds one standard OSBuild SELinux
label stage to the generated manifest. It applies the source policy's dedicated
physical `/ostree` directory label after bootc installation, before qcow2 export;
offline inspection verifies that xattr. All existing stages remain unchanged.
The direct invocation mirrors the pinned CLI's container setup, using its
disposable cache volume and tmpfs-backed `install_exec_t` entry point. This
permits writing image-only SELinux contexts while the host stays enforcing;
no image policy is loaded on the host. Offline inspection reads the stored
ext4 xattr with read-only `debugfs`, avoiding the host's `unlabeled_t` view of
unknown contexts. Native inspection requires `findmnt` and `debugfs`.
The pinned builder's `manifest --help` and `osbuild --help` define this path;
pre-hardening images with the original `usr_t` context keep the original
`image-builder build` path. See [platform hardening](../../docs/platform-hardening.md)
for the observed lock denial and scope of this installation correction.
A failed preflight or build retains its report; an old disk cannot be mistaken
for a successful new run. The fixed builder, immutable input, copied blueprint
and fixed random seed define repeatable inputs, not byte-identical disk files.

`qcow2.toml` requests GPT, a minimum 32 GiB disk and a serial console. It adds
no software, account, password, SSH configuration or service. Access credentials
remain unprovisioned; this is console output configuration for a development
disk, not a login or boot acceptance claim. The OCI image is both the payload
and default buildroot. Image Builder/bootc performs installation, partitioning,
bootloader and deployment mechanics. Preserve the inherited Fedora configuration:

```ini
[composefs]
enabled = yes
[sysroot]
readonly = true
```

The wrapper calls `inspect-qcow2.sh` after construction. It uses `qemu-img`
only for image metadata/conversion and Linux read-only loop mounts, never a
QEMU VM or guestfs appliance. It checks qcow2 format/size, GPT and an ESP,
`BOOTX64.EFI` machine type, BLS and kernel/initramfs files, an OSTree repository
and container deployment origin, and exact matches with the source release
and prepare-root configuration. The recorded partition table is the actual
layout, not a hard-coded partition arrangement. Inspection failures fail the
run and preserve diagnostics. VM boot is reserved for Phase 2B.

The initial macOS/arm64 validation could verify CLI/schema, source identity
and native alternate-root lint, but could not construct or inspect a disk:
amd64 `bootc container lint` returns `Function not implemented (os error 38)`;
the pinned builder's amd64 `crun --version` fails to re-execute through a
memory file descriptor. Native Linux execution of this definition remains
required before Phase 2A can pass.
