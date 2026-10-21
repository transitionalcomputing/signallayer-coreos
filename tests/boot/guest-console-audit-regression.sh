#!/usr/bin/env bash
# Temporary guest-side probe for the 0.0.3.1 console-audit regression.
set -uo pipefail
export LC_ALL=C SYSTEMD_PAGER=cat
port=/dev/virtio-ports/org.signallayer.boot-test
for (( i=0; i<30; i++ )); do
    [[ -e $port ]] && break
    sleep 1
done
[[ -e $port ]] || exit 1
exec 3>"$port"
collect() {
    local key=$1 result output
    shift
    output=$("$@" 3>&- 2>&1; printf '\nSLPROBE_EXIT=%s' "$?")
    result=${output##*$'\n'SLPROBE_EXIT=}
    output=${output%$'\n'SLPROBE_EXIT=*}
    printf '%s\t%s\t' "$key" "$result" >&3
    printf '%s' "$output" | base64 --wrap=0 >&3
    printf '\n' >&3
}
mark() {
    printf '%s\t0\tZG9uZQ==\n' "$1" >&3
}
write_probe() {
    local path=$1
    if printf 'console audit regression\n' >"$path"; then
        rm -f -- "$path"
        return 0
    fi
    return 1
}

for (( i=0; i<60; i++ )); do
    [[ $(systemctl is-active multi-user.target 2>/dev/null) == active ]] && \
      [[ $(systemctl is-active sl-console@tty1.service 2>/dev/null) == active ]] && \
      [[ $(systemctl is-active sl-console@ttyS0.service 2>/dev/null) == active ]] && \
      [[ $(systemctl is-active auditd.service 2>/dev/null) == active ]] && break
    sleep 1
done
sleep 8
collect release cat /usr/lib/signallayer/release
collect bootc_status bootc status --json
collect cmdline cat /proc/cmdline
collect kernel_printk cat /proc/sys/kernel/printk
collect bootc_version bootc --version
collect selinux_before getenforce
collect system_state_before systemctl is-system-running
collect failed_units_before systemctl --failed --no-legend --plain
collect console_units systemctl show sl-console@tty1.service sl-console@ttyS0.service --property=Id,ActiveState,SubState,User,Group,TTYPath,StandardInput,StandardOutput,StandardError,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges
collect console_processes ps --no-headers -o pid,user,tty,label,args -C sl-console
collect console_capabilities sh -c 'for p in $(pgrep -x sl-console); do printf "%s " "$p"; grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb):" "/proc/$p/status" | tr "\n" " "; echo; done'
collect journald_config systemd-analyze cat-config systemd/journald.conf
collect persistent_journal test -d /var/log/journal
collect auditd_state systemctl is-active auditd.service
collect audit_status auditctl -s
mark console_ready
sleep 5

for i in 1 2 3 4 5; do
    collect "session_status_$i" busctl --system call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
    sleep 1
done
sleep 2
collect audit_events_after_status journalctl --boot --no-pager --output=short-monotonic _TRANSPORT=audit
collect auditd_log_after_status cat /var/log/audit/audit.log
mark audit_stimulus_complete
sleep 5

printf '<5>SL_KERN_NOTICE_HIDDEN\n' >/dev/kmsg
printf '<4>SL_KERN_WARNING_VISIBLE\n' >/dev/kmsg
printf '<3>SL_KERN_ERROR_VISIBLE\n' >/dev/kmsg
sleep 1
collect sentinel_journal journalctl --boot --no-pager --output=short-monotonic --dmesg --grep='SL_KERN_'
mark sentinels_emitted
sleep 12

collect selinux_after getenforce
collect system_state_after systemctl is-system-running
collect failed_units_after systemctl --failed --no-legend --plain
collect mounts findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
boot_id=$(cat /proc/sys/kernel/random/boot_id)
collect root_write write_probe "/.sl-console-audit-$boot_id"
collect usr_write write_probe "/usr/.sl-console-audit-$boot_id"
collect auth_policy sha256sum /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf
collect platform_policy sha256sum /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf
collect audit_events_final journalctl --boot --no-pager --output=short-monotonic _TRANSPORT=audit
mark complete
