#!/usr/bin/env bash
# Supplied as a temporary systemd credential, never installed in the OCI image.
set -uo pipefail
export LC_ALL=C SYSTEMD_PAGER=cat
port=/dev/virtio-ports/org.signallayer.boot-test
for (( i=0; i<20; i++ )); do
    [[ -e $port ]] && break
    sleep 1
done
[[ -e $port ]] || { echo 'CoreOS probe: evidence port missing' >&2; exit 1; }
exec 3>"$port"
collect() {
    local key=$1 result output
    shift
    # Pipes allow confined command domains to return stdout without writing
    # a file labelled for this service. Close the evidence FD before exec.
    # A suffix preserves trailing newlines and the command's exit status.
    output=$("$@" 3>&- 2>&1; printf '\nSLPROBE_EXIT=%s' "$?")
    result=${output##*$'\n'SLPROBE_EXIT=}
    output=${output%$'\n'SLPROBE_EXIT=*}
    printf '%s\t%s\t' "$key" "$result" >&3
    printf '%s' "$output" | base64 --wrap=0 >&3
    printf '\n' >&3
}

# Observe normal networking; do not create profiles or change the guest policy.
for (( i=0; i<45; i++ )); do
    [[ -n $(ip -4 -o address show scope global 3>&- 2>/dev/null) ]] && break
    sleep 1
done
sleep 2
collect pid1 cat /proc/1/comm
collect kernel uname -r
collect cmdline cat /proc/cmdline
collect target systemctl is-active multi-user.target
collect system_state systemctl is-system-running
collect failed_units systemctl --failed --no-legend --plain
collect network_manager systemctl is-active NetworkManager.service
collect network_devices nmcli --terse --fields DEVICE,TYPE,STATE,CONNECTION device
collect addresses ip -json address show
collect routes ip -json route show default
collect bootc_status bootc status --json
collect ostree_status ostree admin status
collect ostree_booted test -e /run/ostree-booted
collect release cat /usr/lib/signallayer/release
collect prepare_root cat /usr/lib/ostree/prepare-root.conf
collect mounts findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect selinux getenforce
collect prepare_root_journal journalctl --boot --no-pager --unit ostree-prepare-root.service
collect boot_journal journalctl --boot --no-pager --lines=500

# Require EROFS, not just an access denial. Remove the marker if a write
# unexpectedly succeeds; never leave a mutation behind as a test shortcut.
write_probe() {
    local path=$1
    if (printf 'CoreOS boot test\n' >"$path"); then
        rm -f -- "$path"
        echo 'Unexpected successful write'
        return 0
    else
        return 1
    fi
}
marker=$(cat /proc/sys/kernel/random/boot_id)
collect root_write write_probe "/.slprobe-$marker"
collect usr_write write_probe "/usr/.slprobe-$marker"
printf 'complete\t0\tZG9uZQ==\n' >&3
echo 'CoreOS boot probe: evidence collection complete'
