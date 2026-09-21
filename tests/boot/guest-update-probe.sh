#!/usr/bin/bash
# Temporary Phase 3C KVM probe supplied through a systemd credential.
set -uo pipefail
export LC_ALL=C SYSTEMD_PAGER=cat
exec 3>/dev/virtio-ports/org.signallayer.phase3c-test

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
    if printf 'Phase 3C acceptance\n' >"$path"; then
        rm -f -- "$path"
        echo 'Unexpected successful write'
        return 0
    fi
    return 1
}

for ((i=0; i<60; i++)); do
    [[ -n $(ip -4 -o address show scope global 3>&- 2>/dev/null) ]] && break
    sleep 1
done
systemctl is-system-running --wait 3>&- >/dev/null 2>&1 || true
started=$(date --iso-8601=seconds)
marker=$(cat /proc/sys/kernel/random/boot_id)

collect boot_id_before cat /proc/sys/kernel/random/boot_id
collect target_before systemctl is-active multi-user.target
collect system_state_before systemctl is-system-running
collect failed_before systemctl --failed --no-legend --plain
collect selinux_before getenforce
collect release cat /usr/lib/signallayer/release
collect update_unit systemctl cat sl-update.service
collect update_unit_context ls -lZ /usr/lib/systemd/system/sl-update.service
collect bootc_exec_context ls -lZ /usr/bin/bootc
collect bootc_runtime_context ls -ldZ /run/ostree
collect staged_marker_expected_context matchpathcon -n /run/ostree/staged-deployment
collect initial_bootc bootc status --format=json
collect initial_corectl corectl status --json
collect mounts_before findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect root_write_before write_probe "/.slprobe-$marker"
collect usr_write_before write_probe "/usr/.slprobe-$marker"

mkdir -p /etc/containers/registries.conf.d
cat >/etc/containers/registries.conf.d/99-phase3c-test.conf <<'REGISTRY'
[[registry]]
location = "localhost"
insecure = true
REGISTRY

# Bounded failure path: no proxy is listening yet, so the fixed registry lookup
# fails without changing the running deployment.
failure_boot_id=$(cat /proc/sys/kernel/random/boot_id)
collect failure_start corectl update --json
collect failure_wait wait_for_unit 120
collect failure_result systemctl show sl-update.service --property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus
collect failure_status corectl status --json
collect failure_bootc bootc status --format=json
collect failure_boot_id cat /proc/sys/kernel/random/boot_id
collect failure_target systemctl is-active multi-user.target
collect failure_selinux getenforce
systemctl reset-failed sl-update.service

cat >/run/phase3c-proxy.py <<'PY'
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
python3 /run/phase3c-proxy.py >/run/phase3c-proxy.log 2>&1 &
proxy_pid=$!
for ((i=0; i<100; i++)); do
    curl --silent --fail http://127.0.0.1/v2/ 3>&- >/dev/null 2>&1 && break
    sleep .1
done
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
                } >/run/phase3c-worker-process
                exit 0
            fi
        done
        sleep .05
    done
    echo not-observed >/run/phase3c-worker-process
) &
monitor_pid=$!

start_ns=$(date +%s%N)
collect start_update corectl update --json
end_ns=$(date +%s%N)
printf 'start_update_elapsed_ns\t0\t' >&3
printf '%s' "$((end_ns-start_ns))" | base64 --wrap=0 >&3
printf '\n' >&3
for ((i=0; i<300; i++)); do
    state=$(systemctl show sl-update.service --property=ActiveState --value 2>/dev/null || true)
    [[ $state != inactive && $state != failed ]] && break
    sleep .01
done
collect concurrent_update corectl update --json
collect worker_wait wait_for_unit 600
wait "$monitor_pid" || true

collect worker_process cat /run/phase3c-worker-process
collect worker_result systemctl show sl-update.service --property=Id,Names,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,FragmentPath
collect worker_journal journalctl --boot --no-pager --unit=sl-update.service -o short-precise
collect final_bootc bootc status --format=json
collect staged_marker_context ls -lZ /run/ostree/staged-deployment
collect final_corectl corectl status --json
collect boot_id_after cat /proc/sys/kernel/random/boot_id
collect target_after systemctl is-active multi-user.target
collect system_state_after systemctl is-system-running
collect failed_after systemctl --failed --no-legend --plain
collect selinux_after getenforce
collect mounts_after findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect root_write_after write_probe "/.slprobe-final-$marker"
collect usr_write_after write_probe "/usr/.slprobe-final-$marker"
collect platform_avcs sh -c "journalctl --boot --since '$started' --no-pager -o short-precise | grep -E 'avc:.*sl_platformd_t|sl_platformd_t.*avc:' || true"
collect proxy_log cat /run/phase3c-proxy.log
printf 'complete\t0\tZG9uZQ==\n' >&3
sync
kill "$proxy_pid" 2>/dev/null || true
systemctl poweroff
