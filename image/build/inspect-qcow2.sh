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
lsblk --output NAME,SIZE,FSTYPE,PARTTYPE "$loop"
lsblk --noheadings --raw --paths --output NAME,FSTYPE "$loop" > "$work/devices"
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
grep -q 'container-image-reference=.*localhost/signallayer-coreos:0.0.1' "$origin"
cmp "$report_dir/source-release" "$release"
cat "$release" | tee "$report_dir/deployment-release.txt"
prepare_root="${release%/signallayer/release}/ostree/prepare-root.conf"
cmp "$report_dir/source-prepare-root.conf" "$prepare_root"
cat "$prepare_root" | tee "$report_dir/deployment-prepare-root.conf"
echo 'Offline checks passed: qcow2, size, GPT, x86_64 EFI, BLS, kernel/initramfs, bootc origin and matching CoreOS release/composefs configuration.'
