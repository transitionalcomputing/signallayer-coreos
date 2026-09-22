#!/usr/bin/bash
# Temporary Phase 3F lifecycle probe supplied through a systemd credential.
set -uo pipefail
export LC_ALL=C SYSTEMD_PAGER=cat
exec 3>/dev/virtio-ports/org.signallayer.phase3f-test

collect() {
    local key=$1 output result
    shift
    output=$("$@" 3>&- 2>&1; printf '\nSLPROBE_EXIT=%s' "$?")
    result=${output##*$'\n'SLPROBE_EXIT=}
    output=${output%$'\n'SLPROBE_EXIT=*}
    printf '%s\t%s\t' "$key" "$result" >&3
    printf '%s' "$output" | base64 --wrap=0 >&3
    printf '\n' >&3
}

record() {
    printf '%s\t0\t' "$1" >&3
    printf '%s' "$2" | base64 --wrap=0 >&3
    printf '\n' >&3
}

wait_for_unit() {
    local unit=$1 limit=$2 state
    for ((i=0; i<limit; i++)); do
        state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null || true)
        [[ $state == inactive || $state == failed ]] && return 0
        sleep 1
    done
    return 1
}

write_probe() {
    local path=$1
    if printf 'Phase 3F acceptance\n' >"$path"; then
        rm -f -- "$path"
        echo 'Unexpected successful write'
        return 0
    fi
    return 1
}

wait_ready() {
    for ((i=0; i<60; i++)); do
        [[ -n $(ip -4 -o address show scope global 3>&- 2>/dev/null) ]] && break
        sleep 1
    done
    systemctl is-system-running --wait 3>&- >/dev/null 2>&1 || true
}

collect_health() {
    local suffix=$1 marker
    collect "target_$suffix" systemctl is-active multi-user.target
    collect "system_state_$suffix" systemctl is-system-running
    collect "failed_$suffix" systemctl --failed --no-legend --plain
    collect "platform_service_$suffix" systemctl is-active sl-platformd.service
    collect "network_manager_$suffix" systemctl is-active NetworkManager.service
    collect "address_$suffix" ip -4 -o address show scope global
    collect "route_$suffix" ip -4 route show default
    collect "selinux_$suffix" getenforce
    collect "mounts_$suffix" findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
    marker=$(cat /proc/sys/kernel/random/boot_id)
    collect "root_write_$suffix" write_probe "/.slprobe-$marker"
    collect "usr_write_$suffix" write_probe "/usr/.slprobe-$marker"
}

collect_avcs() {
    local key=$1
    collect "$key" sh -c "journalctl --boot --no-pager -o short-precise | grep -E 'avc:.*(sl_platformd_t|install_t)|((sl_platformd_t|install_t).*avc:)' || true"
}

start_proxy() {
    mkdir -p /etc/containers/registries.conf.d
    cat >/etc/containers/registries.conf.d/99-phase3f-test.conf <<'REGISTRY'
[[registry]]
location = "localhost"
insecure = true
REGISTRY
    cat >/run/phase3f-proxy.py <<'PY'
import select, socket, threading
def relay(client):
    upstream = socket.create_connection(("10.0.2.2", 5000), timeout=10)
    sockets = [client, upstream]
    try:
        while True:
            ready, _, _ = select.select(sockets, [], [], 30)
            for source in ready:
                data = source.recv(131072)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)
    finally:
        client.close()
        upstream.close()
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 80))
listener.listen(32)
while True:
    client, _ = listener.accept()
    threading.Thread(target=relay, args=(client,), daemon=True).start()
PY
    python3 /run/phase3f-proxy.py >/run/phase3f-proxy.log 2>&1 &
    for ((i=0; i<100; i++)); do
        curl --silent --fail http://127.0.0.1/v2/ 3>&- >/dev/null 2>&1 && return 0
        sleep .1
    done
    return 1
}

monitor_worker() {
    local unit=$1 command=$2 output=$3
    for ((i=0; i<6000; i++)); do
        for pid in $(pgrep -x bootc 2>/dev/null || true); do
            cgroup=$(cat "/proc/$pid/cgroup" 2>/dev/null || true)
            cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
            if [[ $cgroup == *"$unit"* && $cmdline == "$command " ]]; then
                {
                    printf 'pid=%s\ncontext=' "$pid"
                    cat "/proc/$pid/attr/current"
                    printf '\ncmdline=%s\ncgroup=%s\n' "$cmdline" "$cgroup"
                } >"$output"
                return 0
            fi
        done
        sleep .01
    done
    echo not-observed >"$output"
    return 1
}

state_dir=/var/lib/signallayer-phase3f
wait_ready
mkdir -p "$state_dir"
chmod 0700 "$state_dir"

if [[ ! -e $state_dir/candidate-activation-requested ]]; then
    collect boot_id_seed cat /proc/sys/kernel/random/boot_id
    collect seed_bootc bootc status --format=json
    collect seed_corectl corectl status --json
    collect_health seed
    collect update_unit systemctl cat sl-update.service
    collect update_unit_label ls -lZ /usr/lib/systemd/system/sl-update.service
    python3 - <<'PY' 3>&-
import json, subprocess, sys
s=json.loads(subprocess.check_output(["bootc","status","--format=json"]))["status"]
c=json.loads(subprocess.check_output(["corectl","status","--json"]))
ok=(s.get("staged") is None and s.get("rollback") is None
    and s.get("rollbackQueued") is False
    and c["update"]["state"] == "idle"
    and c["update"]["reboot_required"] is False
    and c["rollback"]["state"] == "idle"
    and c["rollback"]["reboot_required"] is False)
sys.exit(0 if ok else 1)
PY
    if [[ $? -ne 0 ]]; then
        record complete 'fresh A precondition failed'
        sync
        systemctl poweroff
        exit 1
    fi
    start_proxy
    collect registry_available curl --silent --show-error --dump-header - http://127.0.0.1/v2/
    monitor_worker sl-update.service '/usr/bin/bootc upgrade --quiet' /run/phase3f-update-process &
    update_monitor_pid=$!
    collect start_update corectl update --json
    collect update_wait wait_for_unit sl-update.service 900
    wait "$update_monitor_pid" || true
    collect update_process cat /run/phase3f-update-process
    collect update_result systemctl show sl-update.service --property=ActiveState,SubState,Result,ExecMainStatus
    collect update_journal journalctl --boot --unit=sl-update.service --no-pager -o short-precise
    collect staged_candidate_bootc bootc status --format=json
    collect staged_candidate_corectl corectl status --json
    collect boot_id_staged cat /proc/sys/kernel/random/boot_id
    collect_avcs avcs_seed
    python3 - <<'PY' 3>&-
import json, subprocess, sys
s=json.loads(subprocess.check_output(["bootc","status","--format=json"]))["status"]
sys.exit(0 if s.get("staged") is not None and s["staged"].get("downloadOnly") is False else 1)
PY
    if [[ $? -ne 0 ]]; then
        record complete 'candidate staging failed'
        sync
        systemctl poweroff
        exit 1
    fi
    touch "$state_dir/candidate-activation-requested"
    sync
    record activation_reboot_requested 'systemctl reboot'
    systemctl reboot
    exit 0
fi

if [[ ! -e $state_dir/rollback-reboot-requested ]]; then
    collect boot_id_candidate cat /proc/sys/kernel/random/boot_id
    collect candidate_bootc bootc status --format=json
    collect candidate_corectl corectl status --json
    collect_health candidate
    collect rollback_unit systemctl cat sl-rollback.service
    collect rollback_unit_label ls -lZ /usr/lib/systemd/system/sl-rollback.service
    collect registry_listener sh -c "ss -H -ltn 'sport = :80'"
    collect registry_unavailable curl --connect-timeout 2 --max-time 3 --silent --show-error http://127.0.0.1/v2/

    monitor_worker sl-rollback.service '/usr/bin/bootc rollback' /run/phase3f-rollback-process &
    monitor_pid=$!
    start_ns=$(date +%s%N)
    collect start_rollback corectl rollback --json
    end_ns=$(date +%s%N)
    record start_rollback_elapsed_ns "$((end_ns-start_ns))"
    collect rollback_wait wait_for_unit sl-rollback.service 120
    wait "$monitor_pid" || true
    collect rollback_process cat /run/phase3f-rollback-process
    collect rollback_result systemctl show sl-rollback.service --property=Id,Names,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath
    collect rollback_journal journalctl --boot --unit=sl-rollback.service --no-pager -o short-precise
    collect queued_bootc bootc status --format=json
    collect queued_corectl corectl status --json
    collect boot_id_queued cat /proc/sys/kernel/random/boot_id
    collect registry_still_unavailable curl --connect-timeout 2 --max-time 3 --silent --show-error http://127.0.0.1/v2/
    collect_health queued
    collect_avcs avcs_candidate
    python3 - <<'PY' 3>&-
import json, subprocess, sys
s=json.loads(subprocess.check_output(["bootc","status","--format=json"]))["status"]
sys.exit(0 if s.get("rollbackQueued") is True and s.get("staged") is None else 1)
PY
    if [[ $? -ne 0 ]]; then
        record complete 'rollback queue guard failed'
        sync
        systemctl poweroff
        exit 1
    fi
    touch "$state_dir/rollback-reboot-requested"
    sync
    record rollback_reboot_requested 'systemctl reboot'
    systemctl reboot
    exit 0
fi

collect boot_id_after_rollback cat /proc/sys/kernel/random/boot_id
collect after_rollback_bootc bootc status --format=json
collect after_rollback_corectl corectl status --json
collect_health after_rollback
collect_avcs avcs_after_rollback
record clean_shutdown_requested 'systemctl poweroff'
record complete done
sync
systemctl poweroff
