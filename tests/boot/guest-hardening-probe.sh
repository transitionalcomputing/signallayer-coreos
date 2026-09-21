# Phase 3B extension. This credential is never installed in the image. Fixtures
# only affect this disposable overlay; policy/entry-point labels are observed,
# never repaired here. Keep the preceding 36 checks intact.
security_fixture=/run/slprobe-hardening
security_dropin=/run/systemd/system/sl-platformd.service.d/95-hardening-test.conf
mkdir -p "$security_fixture"
held_pid= client_pid= paused_daemon_pid= monitor_pid= monitor_stop=
cleanup_security() {
    if [[ -n $paused_daemon_pid && -e /proc/$paused_daemon_pid/comm ]]; then
        local daemon_comm
        read -r daemon_comm </proc/"$paused_daemon_pid"/comm
        [[ $daemon_comm == sl-platformd ]] && kill -CONT "$paused_daemon_pid" 2>/dev/null
    fi
    if [[ -n $held_pid && -e /proc/$held_pid/comm ]]; then
        local comm
        read -r comm </proc/"$held_pid"/comm
        [[ $comm == bootc ]] && kill -KILL "$held_pid" 2>/dev/null
    fi
    if [[ -n $monitor_pid ]]; then
        [[ -n $monitor_stop ]] && : >"$monitor_stop"
        wait "$monitor_pid" 2>/dev/null
    fi
    [[ -n $client_pid ]] && wait "$client_pid" 2>/dev/null
    rm -f "$security_dropin"
    systemctl daemon-reload
    systemctl start sl-platformd.service
    rm -rf -- "$security_fixture"
}
trap cleanup_security EXIT
collect security_unit systemctl show sl-platformd.service --property=User,CapabilityBoundingSet,NoNewPrivileges,PrivateTmp,ProtectSystem,ProtectHome,ProtectKernelTunables,ProtectControlGroups,RestrictSUIDSGID,ExecStart,FragmentPath,DropInPaths
collect security_base_dropin cat /usr/lib/systemd/system/service.d/10-timeout-abort.conf
collect security_labels ls -lZ /usr/bin/sl-platformd /usr/bin/bootc /usr/bin/chcon /usr/bin/findmnt /usr/bin/lsblk /usr/bin/mount /usr/lib/signallayer/release /usr/lib/signallayer/openssl.cnf /usr/lib/signallayer/openssl.d/pkcs11-provider.conf
collect security_ostree_lock_directory ls -ldZ /sysroot/ostree
collect security_repo_objects /usr/bin/python3 -c 'from pathlib import Path;import json,os,subprocess;p=Path("/sysroot/ostree/repo/objects");print(json.dumps({"path":str(p),"inode":p.stat().st_ino,"context":os.getxattr(p,"security.selinux").decode().rstrip("\0"),"device":Path(subprocess.check_output(["findmnt","--noheadings","--output","SOURCE","--target",str(p)],text=True).strip()).name}))'
collect security_crypto_configuration /usr/bin/python3 -c 'from pathlib import Path;import hashlib,json,stat;source=Path("/etc/pki/tls/openssl.cnf");copy=Path("/usr/lib/signallayer/openssl.cnf");provider=Path("/usr/lib/signallayer/openssl.d/pkcs11-provider.conf");expected=source.read_bytes().replace(b".include /etc/pki/tls/openssl.d\n",b".include /usr/lib/signallayer/openssl.d\n");print(json.dumps({"configuration_preserved":copy.read_bytes()==expected,"provider_preserved":provider.read_bytes()==Path("/etc/pki/tls/openssl.d/pkcs11-provider.conf").read_bytes(),"provider_set_preserved":sorted(p.name for p in Path("/etc/pki/tls/openssl.d").iterdir())==sorted(p.name for p in provider.parent.iterdir()),"configuration_mode":stat.S_IMODE(copy.stat().st_mode),"provider_mode":stat.S_IMODE(provider.stat().st_mode),"configuration_sha256":hashlib.sha256(copy.read_bytes()).hexdigest(),"provider_sha256":hashlib.sha256(provider.read_bytes()).hexdigest()}))'
collect security_bus_config cat /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf
collect security_domain ps --no-headers -o pid,label,args -C sl-platformd
security_initial_pid=$(systemctl show --value --property=MainPID sl-platformd.service)
collect security_daemon_status cat "/proc/$security_initial_pid/status"
collect security_daemon_executable readlink "/proc/$security_initial_pid/exe"
collect security_modules semodule --list-modules=full
collect security_initial_json /usr/bin/corectl status --json

# Fixed requests use shipped Python/libsystemd; no executable is inserted.
# The host embeds this source in the existing test credential only.
boundary_script=$(cat <<'BOUNDARY_SOURCE'
__SL_BOUNDARY_SOURCE__
BOUNDARY_SOURCE
)
dynamic_boundary() {
    local key=$1 scenario=$2 unit=${3:-slprobe-$2}
    collect "${key}_start" systemd-run --quiet --wait --collect --unit="$unit" --property=DynamicUser=yes --property=StandardOutput=journal --property=StandardError=journal /usr/bin/python3 -c "$boundary_script" "$scenario"
    collect "$key" journalctl --boot --quiet --no-pager --output=cat --unit="$unit.service" _COMM=python3
    collect "${key}_metadata" journalctl --boot --quiet --no-pager --output=json --unit="$unit.service" _COMM=python3
}
daemon_children() {
    local path children=()
    # Linux records children per spawning thread, including Tokio workers.
    for path in /proc/"$1"/task/*/children; do
        [[ -r $path ]] || continue
        read -ra children <"$path"
        (( ${#children[@]} )) && printf '%s ' "${children[@]}"
    done
    return 0
}
monitor_backend_children() {
    local daemon=$1 ready=$2 stop=$3 output=$4 path candidate comm seen=' '
    : >"$output"
    : >"$ready"
    while [[ ! -e $stop ]]; do
        local children=() thread_children=()
        for path in /proc/"$daemon"/task/*/children; do
            [[ -r $path ]] || continue
            read -ra thread_children <"$path"
            children+=("${thread_children[@]}")
        done
        for candidate in "${children[@]}"; do
            [[ -r /proc/$candidate/comm ]] || continue
            read -r comm </proc/"$candidate"/comm
            if [[ $comm == bootc && $seen != *" $candidate "* ]]; then
                printf '%s\n' "$candidate" >>"$output"
                seen+="$candidate "
            fi
        done
        sleep 0.05
    done
}
collect security_name_stop systemctl stop sl-platformd.service
collect security_name_free busctl --system --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.signallayer.Platform1
name_audit_start=$(date '+%Y-%m-%d %H:%M:%S')
collect security_name_denied_audit_since printf '%s\n' "$name_audit_start"
dynamic_boundary security_name_denied own
collect security_name_denied_audit_journal journalctl --boot --quiet --no-pager --output=cat --since="$name_audit_start" _TRANSPORT=audit
collect security_name_restart systemctl start sl-platformd.service
for scenario in unsupported wrong-path wrong-interface invalid-signature; do
    if [[ $scenario == invalid-signature ]]; then
        monitor_ready=$security_fixture/invalid-signature-monitor.ready
        monitor_stop=$security_fixture/invalid-signature-monitor.stop
        monitor_output=$security_fixture/invalid-signature-children
        rm -f "$monitor_ready" "$monitor_stop" "$monitor_output"
        monitor_backend_children "$(systemctl show --value --property=MainPID sl-platformd.service)" "$monitor_ready" "$monitor_stop" "$monitor_output" &
        monitor_pid=$!
        for (( attempt=0; attempt<200; attempt++ )); do
            [[ -e $monitor_ready ]] && break
            sleep 0.01
        done
        collect security_invalid_signature_monitor_ready test -e "$monitor_ready"
        dynamic_boundary "security_$scenario" "$scenario"
        : >"$monitor_stop"
        wait "$monitor_pid"; monitor_result=$?
        monitor_pid=
        collect security_invalid_signature_monitor_stop test "$monitor_result" -eq 0
        collect security_invalid_signature_backend_children cat "$monitor_output"
    else
        dynamic_boundary "security_$scenario" "$scenario"
    fi
    # Preserve whether the production XML policy or application dispatcher
    # rejects this exact root request; do not widen authorization for the test.
    collect "security_root_$scenario" /usr/bin/python3 -c "$boundary_script" "$scenario"
done
dynamic_boundary security_status status
collect security_after_bus_json /usr/bin/corectl status --json
collect security_after_bus_backend bootc status --json

# Hold the REAL fixed bootc child with SIGSTOP. Poll PID 1's service MainPID and
# its direct children using /proc and Bash builtins, avoiding a spawn race from
# a slow repeated external pgrep. No command override or test stub is used.
start_held_observation() {
    local key=$1 comm candidate unused path
    daemon_pid=$(systemctl show --value --property=MainPID sl-platformd.service)
    read -r observation_start unused </proc/uptime
    /usr/bin/corectl status --json >"$security_fixture/$key.json" 2>&1 3>&- &
    client_pid=$!
    held_pid=
    for (( attempt=0; attempt<1000; attempt++ )); do
        local children=() thread_children=()
        for path in /proc/"$daemon_pid"/task/*/children; do
            [[ -r $path ]] || continue
            read -ra thread_children <"$path"
            children+=("${thread_children[@]}")
        done
        for candidate in "${children[@]}"; do
            [[ -e /proc/$candidate/comm ]] || continue
            read -r comm </proc/"$candidate"/comm
            if [[ $comm == bootc ]] && kill -STOP "$candidate" 2>/dev/null; then
                held_pid=$candidate
                collect "${key}_held_pid" printf '%s\n' "$held_pid"
                collect "${key}_held_status" cat "/proc/$held_pid/status"
                collect "${key}_held_domain" cat "/proc/$held_pid/attr/current"
                collect "${key}_held_command" sh -c 'tr "\000" " " <"/proc/$1/cmdline"' slprobe "$held_pid"
                collect "${key}_held_crypto_config" /usr/bin/python3 -c 'from pathlib import Path;import sys;print("\n".join(v.decode() for v in Path("/proc/"+sys.argv[1]+"/environ").read_bytes().split(b"\0") if v.startswith((b"OPENSSL_CONF=", b"SYSTEMD_BYPASS_USERDB=", b"LIBMOUNT_UTAB="))))' "$held_pid"
                collect "${key}_children" daemon_children "$daemon_pid"
                return 0
            fi
        done
        [[ -e /proc/$client_pid ]] || break
        sleep 0.01
    done
    collect "${key}_fixture_failure" printf 'No live bootc child could be stopped\n'
    return 1
}
file_result() { cat "$1"; return "$2"; }
finish_observation() {
    local key=$1 result finish unused
    wait "$client_pid"; result=$?
    client_pid=
    read -r finish unused </proc/uptime
    collect "${key}_result" file_result "$security_fixture/$key.json" "$result"
    collect "${key}_elapsed" awk -v start="$observation_start" -v finish="$finish" 'BEGIN {printf "%.2f\n", finish-start}'
    collect "${key}_child_reaped" test ! -e "/proc/$held_pid"
    held_pid=
}
if start_held_observation security_timeout; then
    collect security_busy /usr/bin/corectl status --json
    collect security_timeout_children_after_busy daemon_children "$daemon_pid"
    finish_observation security_timeout
else
    wait "$client_pid"; client_pid=
fi
collect security_timeout_recovery /usr/bin/corectl status --json
if start_held_observation security_restart_inflight; then
    collect security_restart_inflight_restart systemctl restart sl-platformd.service
    finish_observation security_restart_inflight
else
    wait "$client_pid"; client_pid=
fi
collect security_restart_inflight_recovery /usr/bin/corectl status --json
collect security_restart_inflight_domain ps --no-headers -o pid,label,args -C sl-platformd
for cycle in 1 2; do
    collect "security_restart_${cycle}" systemctl restart sl-platformd.service
    collect "security_restart_${cycle}_json" /usr/bin/corectl status --json
    collect "security_restart_${cycle}_domain" ps --no-headers -o pid,label,args -C sl-platformd
done

# A stopped, still-owned service cannot answer GetStatus. This independently
# exercises the CLI's real 25-second method deadline without a fake bus/server.
paused_daemon_pid=$(systemctl show --value --property=MainPID sl-platformd.service)
collect security_cli_deadline_pid printf '%s\n' "$paused_daemon_pid"
collect security_cli_deadline_stop kill -STOP "$paused_daemon_pid"
read -r cli_deadline_start unused </proc/uptime
collect security_cli_deadline_result /usr/bin/corectl status --json
read -r cli_deadline_finish unused </proc/uptime
collect security_cli_deadline_elapsed awk -v start="$cli_deadline_start" -v finish="$cli_deadline_finish" 'BEGIN {printf "%.2f\n", finish-start}'
collect security_cli_deadline_continue kill -CONT "$paused_daemon_pid"
paused_daemon_pid=
# A disconnected sender's queued observation may finish after SIGCONT; its
# backend is still bounded. Wait beyond the backend deadline before recovery.
sleep 17
collect security_cli_deadline_recovery /usr/bin/corectl status --json

# Harmless confinement proof: valid release content, mode 0644, but shadow_t
# label. Bind it over the fixed metadata path only inside the daemon namespace.
# Actual daemon reading must fail SELinux, rather than DAC or malformed content.
cp /usr/lib/signallayer/release "$security_fixture/denied-release"
chmod 0644 "$security_fixture/denied-release"
collect security_negative_label chcon -t shadow_t "$security_fixture/denied-release"
collect security_negative_fixture ls -lZ "$security_fixture/denied-release"
mkdir -p "${security_dropin%/*}"
printf '[Service]\nBindReadOnlyPaths=%s:/usr/lib/signallayer/release\n' "$security_fixture/denied-release" >"$security_dropin"
collect security_negative_reload systemctl daemon-reload
collect security_negative_restart systemctl restart sl-platformd.service
negative_pid=$(systemctl show --value --property=MainPID sl-platformd.service)
collect security_negative_pid printf '%s\n' "$negative_pid"
collect security_negative_domain cat "/proc/$negative_pid/attr/current"
collect security_negative_json /usr/bin/corectl status --json
rm -f "$security_dropin"
collect security_restore_reload systemctl daemon-reload
collect security_restore_restart systemctl restart sl-platformd.service
collect security_final_active systemctl is-active sl-platformd.service
collect security_final_json /usr/bin/corectl status --json
collect security_final_unprivileged_start systemd-run --quiet --wait --collect --unit=slprobe-hardening-final --property=DynamicUser=yes --property=StandardOutput=journal --property=StandardError=journal /usr/bin/corectl status --json
collect security_final_unprivileged_json journalctl --boot --quiet --no-pager --output=cat --unit=slprobe-hardening-final.service _COMM=corectl
collect security_final_unprivileged_metadata journalctl --boot --quiet --no-pager --output=json --unit=slprobe-hardening-final.service _COMM=corectl
collect security_final_domain ps --no-headers -o pid,label,args -C sl-platformd
collect security_final_backend bootc status --json
collect security_final_unit systemctl show sl-platformd.service --property=DropInPaths,MainPID,ActiveState,SubState
collect security_fixture_cleanup rm -rf -- "$security_fixture"
collect security_fixture_absent test ! -e "$security_fixture"
confined_processes() {
    ps --no-headers -eo pid,ppid,label,args |
        awk '$3 == "system_u:system_r:sl_platformd_t:s0"'
}
collect security_final_confined_processes confined_processes
collect security_final_children daemon_children "$(systemctl show --value --property=MainPID sl-platformd.service)"
collect security_final_backend_processes ps --no-headers -o pid,ppid,label,args -C bootc
collect security_final_system_state systemctl is-system-running
collect security_final_failed_units systemctl --failed --no-legend --plain
collect security_final_selinux getenforce
collect security_final_mounts findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect security_final_root_write write_probe "/.slprobe-hardening-$marker"
collect security_final_usr_write write_probe "/usr/.slprobe-hardening-$marker"
collect security_final_journal journalctl --boot --no-pager --unit=sl-platformd.service
collect security_udisks_state systemctl show udisks2.service --property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus
collect security_udisks_status systemctl status --no-pager --full udisks2.service
collect security_udisks_journal journalctl --boot --no-pager --output=cat --unit=udisks2.service
collect security_polkit_status systemctl status --no-pager --full polkit.service
collect security_polkit_journal journalctl --boot --no-pager --output=cat --unit=polkit.service
collect security_audit_journal journalctl --boot --no-pager --output=cat _TRANSPORT=audit
collect security_audit_json journalctl --boot --no-pager --output=json _TRANSPORT=audit
collect security_audit_file cat /var/log/audit/audit.log
collect security_kernel_journal journalctl --boot --no-pager --output=cat --dmesg
# Export the actually loaded binary for native setools analysis, keeping policy
# development tools out of the guest and image. Compression bounds serial I/O.
collect security_loaded_policy sh -c 'gzip -c /sys/fs/selinux/policy | base64 --wrap=0'
collect security_loaded_policy_hash sha256sum /sys/fs/selinux/policy
collect security_loaded_policy_capabilities sh -c 'for f in /sys/fs/selinux/policy_capabilities/*; do printf "%s=" "${f##*/}"; cat "$f"; done'
trap - EXIT
