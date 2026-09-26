#!/usr/bin/env bash
# Offline inspection with Linux loop devices, without a VM appliance.
set -Eeuo pipefail
[[ $# == 1 && $(uname -s) == Linux && $EUID == 0 ]] || { echo 'Usage: sudo inspect-qcow2.sh DISK (Linux only)' >&2; exit 2; }
disk=$(realpath -- "$1")
report_dir=$(dirname -- "$disk")
qemu-img info --output=json "$disk" | tee "$report_dir/qcow2-info.json"
python3 - "$report_dir/qcow2-info.json" <<'PY'
import json, sys
info = json.load(open(sys.argv[1]))
assert info["format"] == "qcow2", info
assert info["virtual-size"] >= 32 * 1024**3, info
assert not info.get("backing-filename"), info
PY
stat --format='Disk file size: %s bytes' "$disk"
work=$(mktemp -d "$report_dir/inspect.XXXXXXXX")
loop=''
mounts=()
cleanup() {
    result=$?
    trap - EXIT
    for (( i=${#mounts[@]}-1; i>=0; i-- )); do
        umount -- "${mounts[i]}" || result=1
    done
    if [[ -n $loop ]]; then losetup --detach "$loop" || result=1; fi
    # Keep temporary files on cleanup failure so no active mount is removed.
    if (( result == 0 )); then rm -rf -- "$work"; fi
    exit "$result"
}
trap cleanup EXIT
qemu-img convert -f qcow2 -O raw "$disk" "$work/disk.raw"
loop=$(losetup --read-only --partscan --find --show "$work/disk.raw")
sfdisk --verify "$loop"
sfdisk --json "$loop" | tee "$report_dir/partition-table.json"
python3 - "$report_dir/partition-table.json" <<'PY'
import json, sys
table = json.load(open(sys.argv[1]))["partitiontable"]
assert table["label"] == "gpt", table
assert any(p["type"].lower() == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
           for p in table["partitions"]), table
PY
# Probe the read-only media directly; reused loop devices can retain incomplete
# udev properties after partscan even when their filesystems are valid.
lsblk --properties-by blkid --output NAME,SIZE,FSTYPE,PARTTYPE "$loop"
lsblk --properties-by blkid --noheadings --raw --paths --output NAME,FSTYPE "$loop" > "$work/devices"
while read -r device fs; do
    case "$fs" in
        ext4) options=ro,noload ;;
        vfat) options=ro ;;
        *) continue ;;
    esac
    target="$work/$(basename -- "$device")"
    mkdir "$target"
    mount -o "$options" "$device" "$target"
    mounts+=("$target")
done < "$work/devices"
(( ${#mounts[@]} > 0 ))
efi=$(find "${mounts[@]}" -type f -iname BOOTX64.EFI -print -quit)
[[ -n $efi ]]
file "$efi" | tee "$report_dir/efi-file.txt"
[[ $(file "$efi") == *x86-64* ]]
bls=$(find "${mounts[@]}" -type f -path '*/loader*/entries/*.conf' -print -quit)
[[ -n $bls ]]
cat "$bls" | tee "$report_dir/bls-entry.txt"
kernel=$(find "${mounts[@]}" -type f -path '*/ostree/*' -name 'vmlinuz*' -print -quit)
initramfs=$(find "${mounts[@]}" -type f -path '*/ostree/*' -name 'initramfs*' -print -quit)
[[ -n $kernel && -s $kernel && -n $initramfs && -s $initramfs ]]
repo=$(find "${mounts[@]}" -type f -path '*/ostree/repo/config' -print -quit)
origin=$(find "${mounts[@]}" -type f -path '*/ostree/deploy/*/deploy/*.origin' -print -quit)
release=$(find "${mounts[@]}" -type f -path '*/ostree/deploy/*/deploy/*/usr/lib/signallayer/release' -print -quit)
[[ -n $repo && -n $origin && -n $release ]]
cat "$origin" | tee "$report_dir/deployment-origin.txt"
grep -q 'container-image-reference=.*localhost/signallayer-coreos:0.0.2' "$origin"
cmp "$report_dir/source-release" "$release"
if [[ -f $report_dir/source-ostree-context ]]; then
    # The host kernel presents image-only contexts as unlabeled_t to callers
    # without MAC_ADMIN. Read the stored ext4 xattr directly, without -w or
    # loading the image policy into the host.
    root_device=$(findmnt --noheadings --output SOURCE --target "${repo%/repo/config}")
    debugfs -R "ea_get -f \"$work/ostree-context.raw\" /ostree security.selinux" "$root_device"
    python3 - "$repo" "$report_dir/source-ostree-context" "$report_dir/ostree-context.json" "$work/ostree-context.raw" <<'PY'
import json, os, pathlib, sys
directory = pathlib.Path(sys.argv[1]).parent.parent
expected = pathlib.Path(sys.argv[2]).read_text().strip()
actual = pathlib.Path(sys.argv[4]).read_bytes().decode().rstrip("\0")
report = {"directory": str(directory), "expected": expected, "actual": actual,
          "reader": "debugfs (read-only ext4 xattr)",
          "host_view": os.getxattr(directory, "security.selinux").decode().rstrip("\0"),
          "matches_image_policy": actual == expected}
pathlib.Path(sys.argv[3]).write_text(json.dumps(report, indent=2) + "\n")
assert report["matches_image_policy"], report
print("Physical OSTree directory label matches the source image policy:", actual)
PY
fi
cat "$release" | tee "$report_dir/deployment-release.txt"
prepare_root="${release%/signallayer/release}/ostree/prepare-root.conf"
cmp "$report_dir/source-prepare-root.conf" "$prepare_root"
cat "$prepare_root" | tee "$report_dir/deployment-prepare-root.conf"
echo 'Offline checks passed: qcow2, size, GPT, x86_64 EFI, BLS, kernel/initramfs, bootc origin and matching CoreOS release/composefs configuration.'
