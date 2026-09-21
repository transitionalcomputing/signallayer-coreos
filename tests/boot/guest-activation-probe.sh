#!/usr/bin/bash
# Temporary Phase 3D lifecycle probe supplied through a systemd credential.
set -uo pipefail
export LC_ALL=C SYSTEMD_PAGER=cat
exec 3>/dev/virtio-ports/org.signallayer.phase3d-test

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
    local limit=$1 state
    for ((i=0; i<limit; i++)); do
        state=$(systemctl show sl-update.service --property=ActiveState --value 2>/dev/null || true)
        [[ $state == inactive || $state == failed ]] && return 0
        sleep 1
    done
    return 1
}

write_probe() {
    local path=$1
    if printf 'Phase 3D acceptance\n' >"$path"; then
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

collect_avcs() {
    local key=$1 since=$2
    collect "$key" sh -c "journalctl --boot --since '$since' --no-pager -o short-precise | grep -E 'avc:.*(sl_platformd_t|install_t)|((sl_platformd_t|install_t).*avc:)' || true"
}

start_proxy() {
    mkdir -p /etc/containers/registries.conf.d
    cat >/etc/containers/registries.conf.d/99-phase3d-test.conf <<'REGISTRY'
[[registry]]
location = "localhost"
insecure = true
REGISTRY
    cat >/run/phase3d-proxy.py <<'PY'
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
    python3 /run/phase3d-proxy.py >/run/phase3d-proxy.log 2>&1 &
    proxy_pid=$!
    for ((i=0; i<100; i++)); do
        curl --silent --fail http://127.0.0.1/v2/ 3>&- >/dev/null 2>&1 && break
        sleep .1
    done
}

state_dir=/var/lib/signallayer-phase3d
wait_ready
started=$(date --iso-8601=seconds)

if [[ ! -e $state_dir/reboot-requested ]]; then
    mkdir -p "$state_dir"
    chmod 0700 "$state_dir"
    collect boot_id_initial cat /proc/sys/kernel/random/boot_id
    collect target_initial systemctl is-active multi-user.target
    collect system_state_initial systemctl is-system-running
    collect failed_initial systemctl --failed --no-legend --plain
    collect platform_service_initial systemctl is-active sl-platformd.service
    collect network_manager_initial systemctl is-active NetworkManager.service
    collect address_initial ip -4 -o address show scope global
    collect route_initial ip -4 route show default
    collect selinux_initial getenforce
    collect initial_bootc bootc status --format=json
    collect initial_corectl corectl status --json
    collect mounts_initial findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
    marker=$(cat /proc/sys/kernel/random/boot_id)
    collect root_write_initial write_probe "/.slprobe-$marker"
    collect usr_write_initial write_probe "/usr/.slprobe-$marker"
    collect update_unit systemctl cat sl-update.service
    collect runtime_context ls -ldZ /run/ostree

    start_proxy
    collect registry_probe curl --silent --show-error --dump-header - http://127.0.0.1/v2/
    (
        for ((i=0; i<2400; i++)); do
            for pid in $(pgrep -x bootc 2>/dev/null || true); do
                cgroup=$(cat "/proc/$pid/cgroup" 2>/dev/null || true)
                cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
                if [[ $cgroup == *sl-update.service* && $cmdline == '/usr/bin/bootc upgrade --quiet ' ]]; then
                    {
                        printf 'pid=%s\ncontext=' "$pid"
                        cat "/proc/$pid/attr/current"
                        printf '\ncmdline=%s\ncgroup=%s\n' "$cmdline" "$cgroup"
                    } >/run/phase3d-worker-process
                    exit 0
                fi
            done
            sleep .05
        done
        echo not-observed >/run/phase3d-worker-process
    ) &
    monitor_pid=$!

    start_ns=$(date +%s%N)
    collect start_update corectl update --json
    end_ns=$(date +%s%N)
    record start_update_elapsed_ns "$((end_ns-start_ns))"
    for ((i=0; i<300; i++)); do
        state=$(systemctl show sl-update.service --property=ActiveState --value 2>/dev/null || true)
        [[ $state != inactive && $state != failed ]] && break
        sleep .01
    done
    collect concurrent_update corectl update --json
    collect worker_wait wait_for_unit 600
    wait "$monitor_pid" || true
    collect worker_process cat /run/phase3d-worker-process
    collect worker_result systemctl show sl-update.service --property=Id,Names,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath
    collect before_reboot_bootc bootc status --format=json
    collect before_reboot_corectl corectl status --json
    collect staged_marker_context ls -lZ /run/ostree/staged-deployment
    collect boot_id_before_reboot cat /proc/sys/kernel/random/boot_id
    collect_avcs relevant_avcs_before "$started"

    python3 - <<'PY' 3>&-
import json, subprocess, sys
status=json.loads(subprocess.check_output(["bootc", "status", "--format=json"]))["status"]
sys.exit(0 if status.get("staged") is not None and status["staged"].get("downloadOnly") is False else 1)
PY
    if [[ $? -ne 0 ]]; then
        record stage_guard failed
        printf 'complete\t1\tZmFpbGVk\n' >&3
        sync
        systemctl poweroff
        exit 1
    fi
    touch "$state_dir/reboot-requested"
    sync
    record reboot_requested 'systemctl reboot'
    systemctl reboot
    exit 0
fi

collect boot_id_after_reboot cat /proc/sys/kernel/random/boot_id
collect target_after systemctl is-active multi-user.target
collect system_state_after systemctl is-system-running
collect failed_after systemctl --failed --no-legend --plain
collect platform_service_after systemctl is-active sl-platformd.service
collect network_manager_after systemctl is-active NetworkManager.service
collect address_after ip -4 -o address show scope global
collect route_after ip -4 route show default
collect selinux_after getenforce
collect after_reboot_bootc bootc status --format=json
collect after_reboot_corectl corectl status --json
collect staged_marker_absent_after_reboot test ! -e /run/ostree/staged-deployment
collect mounts_after findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
marker=$(cat /proc/sys/kernel/random/boot_id)
collect root_write_after write_probe "/.slprobe-$marker"
collect usr_write_after write_probe "/usr/.slprobe-$marker"
collect_avcs relevant_avcs_after "$started"
printf 'complete\t0\tZG9uZQ==\n' >&3
sync
systemctl poweroff
