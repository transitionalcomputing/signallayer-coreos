#!/usr/bin/env bash
set -uo pipefail

state=/var/lib/sl-candidate-c-evidence
evidence=$state/guest-evidence.tsv
port=/dev/virtio-ports/org.signallayer.candidatec
unit=sl-candidate-c-fixture.service
fixture_mount=/mnt/sl-candidate-c-fixture
rootfs_source=/var/lib/sl-candidate-c/rootfs-source
rootfs_mount=/run/sl-candidate-c/rootfs
runtime_home=/var/lib/sl-candidate-c/home
runtime_data=/var/lib/sl-candidate-c/data
runtime_graph=/var/lib/sl-candidate-c/containers/storage
runtime_run=/run/sl-management/containers
config_dir=/run/sl-candidate-c/config
rootless_socket=/run/sl-management/podman/podman.sock
mkdir -p "$state"
: > "$evidence"

record() {
    local key=$1 output rc
    shift
    set +e
    output=$("$@" 2>&1)
    rc=$?
    set -e
    printf '%s\t%s\t%s\n' "$key" "$rc" "$(printf %s "$output" | base64 -w0)" >> "$evidence"
    return 0
}

record_sh() {
    local key=$1 command=$2 output rc
    set +e
    output=$(bash -o pipefail -c "$command" 2>&1)
    rc=$?
    set -e
    printf '%s\t%s\t%s\n' "$key" "$rc" "$(printf %s "$output" | base64 -w0)" >> "$evidence"
    return 0
}

fail() {
    record failure printf '%s' "$1"
    record failure_journal journalctl -u "$unit" -b --no-pager
    cat "$evidence" > "$port" 2>/dev/null || true
    sync
    systemctl poweroff --force
    exit 1
}

finish() {
    record complete printf 'candidate-c probe complete'
    cat "$evidence" > "$port"
    sync
    systemctl poweroff
}

runtime_env=(
    HOME="$runtime_home"
    XDG_CONFIG_HOME=/run/sl-candidate-c/config-home
    XDG_DATA_HOME="$runtime_data"
    XDG_RUNTIME_DIR=/run/sl-management
    CONTAINERS_STORAGE_CONF="$config_dir/storage.conf"
    CONTAINERS_CONF="$config_dir/containers.conf"
    CONTAINERS_REGISTRIES_CONF="$config_dir/registries.conf"
    REGISTRY_AUTH_FILE="$config_dir/auth.json"
)

podman_user() {
    runuser -u sl-management -- env "${runtime_env[@]}" podman \
        --root "$runtime_graph" --runroot "$runtime_run" --storage-driver overlay "$@"
}

namespace_report() {
    local pid=$1 name
    for name in user mnt pid ipc net uts cgroup; do
        printf 'host_%s=%s\n' "$name" "$(readlink "/proc/1/ns/$name")"
        printf 'container_%s=%s\n' "$name" "$(readlink "/proc/$pid/ns/$name")"
    done
}

process_report() {
    local pid=$1 cgroup main_pid pids
    cgroup=$(systemctl show "$unit" -p ControlGroup --value)
    main_pid=$(systemctl show "$unit" -p MainPID --value)
    printf 'unit_cgroup=%s\nmain_pid=%s\ncontainer_pid=%s\n' "$cgroup" "$main_pid" "$pid"
    pids=$(find "/sys/fs/cgroup$cgroup" -name cgroup.procs -type f -exec cat '{}' + 2>/dev/null | sort -nu | paste -sd, -)
    printf 'cgroup_pids=%s\n' "$pids"
    if [[ -n $pids ]]; then
        ps -o pid=,ppid=,uid=,gid=,label=,comm=,args= -p "$pids"
    fi
}

socket_state() {
    local count
    count=$(awk -v path="$rootless_socket" '$8 == path {count++} END {print count+0}' /proc/net/unix)
    printf 'present=%s\n' "$count"
    [[ $count == 0 ]]
}

record pinned_origin bootc status --format=json
record kernel uname -a
record os_release cat /etc/os-release
record pid1 cat /proc/1/comm
record systemd systemctl --version
record selinux getenforce
record cgroup_mount findmnt -no FSTYPE,OPTIONS /sys/fs/cgroup
record podman_version podman version
record crun_version crun --version

if ! getent passwd sl-management >/dev/null; then
    useradd --system --user-group --home-dir "$runtime_home" --shell /usr/sbin/nologin sl-management || fail useradd
fi
usermod --lock sl-management || fail userlock
uid=$(id -u sl-management)
gid=$(id -g sl-management)
start=100000
while awk -F: -v start="$start" -v count=65536 '
    NF == 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        end = start + count; other_end = $2 + $3
        if (start < other_end && $2 < end) conflict=1
    }
    END { exit conflict ? 0 : 1 }
' /etc/subuid /etc/subgid; do
    start=$((start + 65536))
done
grep -q '^sl-management:' /etc/subuid || printf 'sl-management:%s:65536\n' "$start" >> /etc/subuid
grep -q '^sl-management:' /etc/subgid || printf 'sl-management:%s:65536\n' "$start" >> /etc/subgid

install -d -m 0755 -o root -g root /var/lib/sl-candidate-c /run/sl-candidate-c /run/sl-candidate-c/config-home
install -d -m 0700 -o sl-management -g sl-management "$runtime_home" "$runtime_data" "$runtime_graph" /run/sl-management "$runtime_run"
install -d -m 0755 -o root -g root "$config_dir" "$rootfs_source" "$rootfs_mount" "$fixture_mount"
cat > "$config_dir/storage.conf" <<EOF
[storage]
driver = "overlay"
runroot = "$runtime_run"
graphroot = "$runtime_graph"
EOF
cat > "$config_dir/containers.conf" <<'EOF'
[engine]
events_logger = "file"
runtime = "crun"
cgroup_manager = "cgroupfs"
EOF
cat > "$config_dir/registries.conf" <<'EOF'
unqualified-search-registries = []
EOF
printf '{}\n' > "$config_dir/auth.json"
chmod 0644 "$config_dir"/*
chown root:root "$config_dir"/*

install -d -m 0700 -o sl-management -g sl-management "$runtime_home/.config/containers"
printf '[engine]\nruntime="definitely-invalid"\n' > "$runtime_home/.config/containers/containers.conf"
chown -R sl-management:sl-management "$runtime_home/.config"
record hostile_user_config find "$runtime_home/.config" -type f -maxdepth 3 -exec ls -l '{}' ';' -exec cat '{}' ';'

mount -o ro /dev/vdb "$fixture_mount" || fail fixture_mount
fixture_ref=$(cat "$fixture_mount/fixture.ref")
record fixture_archive_sha sha256sum "$fixture_mount/fixture.oci.tar"
record fixture_provenance cat "$fixture_mount/provenance.txt"
podman load -i "$fixture_mount/fixture.oci.tar" > "$state/rootful-load.log" 2>&1 || fail fixture_load
cid=$(podman create "$fixture_ref") || fail fixture_create
podman export "$cid" | tar --numeric-owner --xattrs --xattrs-include='*' -C "$rootfs_source" -xf - || fail fixture_export
podman rm "$cid" >/dev/null || fail fixture_remove
umount "$fixture_mount" || fail fixture_unmount
# The scratch fixture intentionally contains only its binary and dynamic loader.
# Podman prepares standard bind targets before launch, so a valid exploded
# rootfs must provide those directories/files before the source becomes read-only.
install -d -m 0755 "$rootfs_source/etc" "$rootfs_source/run" \
    "$rootfs_source/proc" "$rootfs_source/sys" "$rootfs_source/sys/fs" \
    "$rootfs_source/sys/fs/cgroup" "$rootfs_source/dev" "$rootfs_source/dev/pts" \
    "$rootfs_source/dev/shm" "$rootfs_source/tmp" "$rootfs_source/var" \
    "$rootfs_source/var/tmp" "$rootfs_source/home" "$rootfs_source/root" \
    "$rootfs_source/opt" "$rootfs_source/srv" "$rootfs_source/mnt" "$rootfs_source/media"
ln -s /run "$rootfs_source/var/run"
install -m 0644 /dev/null "$rootfs_source/etc/hosts"
install -m 0644 /dev/null "$rootfs_source/etc/hostname"
install -m 0644 /dev/null "$rootfs_source/etc/resolv.conf"
ln -s /proc/mounts "$rootfs_source/etc/mtab"
install -m 0644 /dev/null "$rootfs_source/run/.containerenv"
chown -R root:root "$rootfs_source"
chmod -R go-w "$rootfs_source"
chcon -R -t container_file_t "$rootfs_source" || fail rootfs_label
mount --bind "$rootfs_source" "$rootfs_mount" || fail rootfs_bind
mount -o remount,bind,ro "$rootfs_mount" || fail rootfs_readonly

record identity id sl-management
record passwd_entry getent passwd sl-management
record subuid grep '^sl-management:' /etc/subuid
record subgid grep '^sl-management:' /etc/subgid
record rootfs_source_stat stat -c 'uid=%u gid=%g mode=%a type=%F' "$rootfs_source"
record rootfs_source_context stat -c '%C' "$rootfs_source" "$rootfs_source/usr/bin/sl-phase1-fixture"
record_sh rootfs_manifest "find '$rootfs_source' -xdev -printf '%P\t%y\t%U\t%G\t%m\t%s\n' | sort"
record rootfs_mount findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$rootfs_mount"
record rootfs_binary_sha sha256sum "$rootfs_mount/usr/bin/sl-phase1-fixture"
record rootfs_runtime_write runuser -u sl-management -- touch "$rootfs_mount/usr/bin/sl-candidate-c-write"

cat > "/run/systemd/system/$unit" <<EOF
[Unit]
Description=Disposable SignalLayer Candidate C rootfs fixture
After=local-fs.target

[Service]
Type=simple
User=sl-management
Group=sl-management
Environment=HOME=$runtime_home
Environment=XDG_CONFIG_HOME=/run/sl-candidate-c/config-home
Environment=XDG_DATA_HOME=$runtime_data
Environment=XDG_RUNTIME_DIR=/run/sl-management
Environment=CONTAINERS_STORAGE_CONF=$config_dir/storage.conf
Environment=CONTAINERS_CONF=$config_dir/containers.conf
Environment=CONTAINERS_REGISTRIES_CONF=$config_dir/registries.conf
Environment=REGISTRY_AUTH_FILE=$config_dir/auth.json
ExecStart=/usr/bin/podman --root $runtime_graph --runroot $runtime_run --storage-driver overlay run --rootfs --rm --replace --name sl-candidate-c-fixture --network=none --read-only --security-opt=no-new-privileges --cap-drop=all --runtime=crun $rootfs_mount /usr/bin/sl-phase1-fixture
ExecStop=/usr/bin/podman --root $runtime_graph --runroot $runtime_run --storage-driver overlay stop -t 5 sl-candidate-c-fixture
Restart=no
KillMode=mixed
Delegate=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=$rootfs_mount $config_dir /run/sl-candidate-c/config-home
ReadWritePaths=$runtime_home $runtime_data $runtime_graph /run/sl-management
EOF
chmod 0644 "/run/systemd/system/$unit"
chown root:root "/run/systemd/system/$unit"
systemctl daemon-reload
systemctl start "$unit" || { record start_failure journalctl -u "$unit" -b --no-pager; fail service_start; }
stable=0
for _ in {1..30}; do
    if systemctl is-active --quiet "$unit" && podman_user container exists sl-candidate-c-fixture; then
        stable=$((stable + 1))
        [[ $stable -ge 3 ]] && break
    else
        stable=0
    fi
    sleep 1
done
if [[ $stable -lt 3 ]]; then
    record start_failure journalctl -u "$unit" -b --no-pager
    fail service_inactive
fi

record unit systemctl cat "$unit"
record unit_properties systemctl show "$unit" -p User -p Group -p Delegate -p ControlGroup -p MainPID -p FragmentPath -p Environment -p ReadOnlyPaths -p ReadWritePaths
record rootless_info podman_user info --format=json
record container_inspect podman_user inspect sl-candidate-c-fixture
container_pid=$(podman_user inspect -f '{{.State.Pid}}' sl-candidate-c-fixture) || fail inspect_pid
record container_uid_map cat "/proc/$container_pid/uid_map"
record container_gid_map cat "/proc/$container_pid/gid_map"
record container_status cat "/proc/$container_pid/status"
record container_selinux cat "/proc/$container_pid/attr/current"
record container_cgroup cat "/proc/$container_pid/cgroup"
record container_namespaces namespace_report "$container_pid"
record container_mountinfo cat "/proc/$container_pid/mountinfo"
record process_relationships process_report "$container_pid"
record fixture_log podman_user logs sl-candidate-c-fixture
record socket_state socket_state
record rootless_socket runuser -u sl-management -- test -S "$rootless_socket"

systemctl stop "$unit" || fail service_stop
record service_stop systemctl is-active "$unit"
record container_exists_after_stop podman_user container exists sl-candidate-c-fixture
record missing_rootfs runuser -u sl-management -- env "${runtime_env[@]}" podman \
    --root "$runtime_graph" --runroot "$runtime_run" --storage-driver overlay \
    run --rootfs --rm --name sl-candidate-c-missing --network=none --read-only \
    --security-opt=no-new-privileges --cap-drop=all --runtime=crun \
    /run/sl-candidate-c/missing-rootfs /usr/bin/sl-phase1-fixture
record system_state_after_failure systemctl is-system-running
record network_after_failure systemctl is-active NetworkManager
record native_target_after_failure systemctl is-active multi-user.target
record failed_units_after_failure systemctl --failed --no-legend --plain

systemctl start "$unit" || fail recovery_start
stable=0
for _ in {1..30}; do
    if systemctl is-active --quiet "$unit" && podman_user container exists sl-candidate-c-fixture; then
        stable=$((stable + 1))
        [[ $stable -ge 3 ]] && break
    else
        stable=0
    fi
    sleep 1
done
if [[ $stable -lt 3 ]]; then
    record recovery_failure journalctl -u "$unit" -b --no-pager
    fail recovery_inactive
fi
record service_recovery systemctl is-active "$unit"
record container_inspect_recovery podman_user inspect sl-candidate-c-fixture
container_pid=$(podman_user inspect -f '{{.State.Pid}}' sl-candidate-c-fixture) || fail recovery_inspect_pid
record process_relationships_recovery process_report "$container_pid"
record fixture_log_recovery podman_user logs sl-candidate-c-fixture
systemctl stop "$unit" || fail recovery_stop
record service_stop_final systemctl is-active "$unit"
record container_exists_final podman_user container exists sl-candidate-c-fixture
record selinux_after getenforce
record audit journalctl -k -b -g 'avc:.*denied' --no-pager --output=json
finish
