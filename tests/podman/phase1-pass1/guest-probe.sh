#!/usr/bin/env bash
set -uo pipefail

state=/var/lib/sl-phase1-pass1
evidence=$state/evidence.tsv
port=/dev/virtio-ports/org.signallayer.phase1
unit=sl-management-fixture.service
mkdir -p "$state"

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

finish() {
    record complete printf 'pass1 probe complete'
    cat "$evidence" > "$port"
    sync
    systemctl poweroff
}

fail() {
    record failure printf '%s' "$1"
    cat "$evidence" > "$port" 2>/dev/null || true
    sync
    systemctl poweroff --force
    exit 1
}

if [[ ! -e $state/boot1-complete ]]; then
    : > "$evidence"
    record pinned_origin bootc status --format=json
    record kernel uname -a
    record os_release cat /etc/os-release
    record pid1 cat /proc/1/comm
    record systemd systemctl --version
    record selinux getenforce
    record selinux_policy sestatus
    record cgroup_mount findmnt -no FSTYPE,OPTIONS /sys/fs/cgroup
    record podman_version podman version
    record crun_version crun --version
    record accounts_before getent passwd
    record subuid_before cat /etc/subuid
    record subgid_before cat /etc/subgid

    if ! getent passwd sl-management >/dev/null; then
        useradd --system --user-group --home-dir /var/lib/sl-management \
            --shell /usr/sbin/nologin sl-management || fail useradd
    fi
    usermod --lock sl-management || fail userlock
    uid=$(id -u sl-management)
    gid=$(id -g sl-management)

    # Select the first aligned range absent from both subordinate-ID databases.
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

    install -d -m 0700 -o sl-management -g sl-management /var/lib/sl-management /run/sl-management
    install -d -m 0700 -o sl-management -g sl-management \
        /var/lib/sl-management/containers/storage /run/sl-management/containers
    cat > /etc/containers/storage-sl-management.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/run/sl-management/containers"
graphroot = "/var/lib/sl-management/containers/storage"
EOF
    cat > /etc/containers/containers-sl-management.conf <<'EOF'
[engine]
events_logger = "file"
runtime = "crun"
EOF
    chmod 0644 /etc/containers/storage-sl-management.conf /etc/containers/containers-sl-management.conf
    chown root:root /etc/containers/storage-sl-management.conf /etc/containers/containers-sl-management.conf

    install -d -m 0755 /mnt/sl-phase1-fixture
    mount -o ro /dev/vdb /mnt/sl-phase1-fixture || fail fixture_mount
    fixture_ref=$(cat /mnt/sl-phase1-fixture/fixture.ref)
    record fixture_archive_sha sha256sum /mnt/sl-phase1-fixture/fixture.oci.tar
    record fixture_provenance cat /mnt/sl-phase1-fixture/provenance.txt
    if ! runuser -u sl-management -- env HOME=/var/lib/sl-management \
        XDG_RUNTIME_DIR=/run/sl-management \
        CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf \
        CONTAINERS_CONF=/etc/containers/containers-sl-management.conf \
        podman load -i /mnt/sl-phase1-fixture/fixture.oci.tar >> "$state/load.log" 2>&1; then
        record fixture_load cat "$state/load.log"
        fail fixture_load
    fi
    umount /mnt/sl-phase1-fixture

    cat > "/etc/systemd/system/$unit" <<EOF
[Unit]
Description=SignalLayer Phase 1 rootless bootstrap fixture
After=local-fs.target

[Service]
Type=simple
User=sl-management
Group=sl-management
Environment=HOME=/var/lib/sl-management
Environment=XDG_RUNTIME_DIR=/run/sl-management
Environment=CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf
Environment=CONTAINERS_CONF=/etc/containers/containers-sl-management.conf
RuntimeDirectory=sl-management
RuntimeDirectoryMode=0700
StateDirectory=sl-management
StateDirectoryMode=0700
ExecStart=/usr/bin/podman --root /var/lib/sl-management/containers/storage --runroot /run/sl-management/containers --storage-driver overlay run --rm --replace --name sl-management-fixture --pull=never --network=none --read-only --security-opt=no-new-privileges --cap-drop=all $fixture_ref
ExecStop=/usr/bin/podman --root /var/lib/sl-management/containers/storage --runroot /run/sl-management/containers --storage-driver overlay stop -t 5 sl-management-fixture
Restart=on-failure
RestartSec=2s
Delegate=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/sl-management /run/sl-management

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "/etc/systemd/system/$unit"
    chown root:root "/etc/systemd/system/$unit"
    systemctl daemon-reload
    systemctl enable --now "$unit" || { record service_start journalctl -u "$unit" -b --no-pager; fail service_start; }
    for _ in {1..30}; do
        systemctl is-active --quiet "$unit" && break
        sleep 1
    done
    systemctl is-active --quiet "$unit" || fail service_inactive

    record identity id sl-management
    record passwd_entry getent passwd sl-management
    record shadow_entry getent shadow sl-management
    record subuid_after grep '^sl-management:' /etc/subuid
    record subgid_after grep '^sl-management:' /etc/subgid
    record unit_before_reboot systemctl cat "$unit"
    record unit_security systemd-analyze security "$unit" --no-pager
    record unit_properties systemctl show "$unit" -p User -p Group -p Delegate -p ControlGroup -p MainPID -p FragmentPath -p Environment -p ReadWritePaths
    record rootless_info runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman info --format=json
    record container_inspect runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman inspect sl-management-fixture
    container_pid=$(runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman inspect -f '{{.State.Pid}}' sl-management-fixture)
    record container_uid_map cat "/proc/$container_pid/uid_map"
    record container_gid_map cat "/proc/$container_pid/gid_map"
    record container_status cat "/proc/$container_pid/status"
    record container_selinux cat "/proc/$container_pid/attr/current"
    record container_cgroup cat "/proc/$container_pid/cgroup"
    record fixture_log runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman logs sl-management-fixture

    record_sh attack_unit_replace "runuser -u sl-management -- sh -c 'printf attack >> /etc/systemd/system/$unit'"
    record_sh attack_unit_dropin "runuser -u sl-management -- mkdir -p /etc/systemd/system/$unit.d"
    record_sh attack_storage_config "runuser -u sl-management -- sh -c 'printf attack >> /etc/containers/storage-sl-management.conf'"
    record_sh attack_systemctl_stop "runuser -u sl-management -- systemctl stop $unit"
    record_sh attack_systemctl_start "runuser -u sl-management -- systemctl start $unit"
    record_sh attack_user_manager "runuser -u sl-management -- env XDG_RUNTIME_DIR=/run/user/$uid systemctl --user start $unit"
    record_sh attack_rootful_socket "runuser -u sl-management -- test -S /run/podman/podman.sock"
    record_sh attack_rootless_socket "runuser -u sl-management -- test -S /run/sl-management/podman/podman.sock"
    record_sh attack_privileged_state "runuser -u sl-management -- sh -c 'printf attack > /etc/sl-phase1-attack'"
    record_sh attack_boot_state "runuser -u sl-management -- sh -c 'printf attack > /boot/sl-phase1-attack'"

    # Deliberately place hostile per-user defaults. The root-owned unit pins its
    # configuration and immutable image reference, so these must not affect boot.
    install -d -m 0700 -o sl-management -g sl-management /var/lib/sl-management/.config/containers
    printf '[engine]\nruntime="definitely-invalid"\n' > /var/lib/sl-management/.config/containers/containers.conf
    printf '[storage]\ngraphroot="/tmp/attacker-store"\n' > /var/lib/sl-management/.config/containers/storage.conf
    chown -R sl-management:sl-management /var/lib/sl-management/.config
    record hostile_user_config find /var/lib/sl-management/.config -type f -maxdepth 3 -exec ls -l '{}' ';' -exec cat '{}' ';'

    touch "$state/boot1-complete"
    record boot_id_before cat /proc/sys/kernel/random/boot_id
    sync
    systemctl reboot
    exit 0
fi

record boot_id_after cat /proc/sys/kernel/random/boot_id
record service_after_reboot systemctl is-active "$unit"
record service_enabled systemctl is-enabled "$unit"
record unit_after_reboot systemctl cat "$unit"
record system_state systemctl is-system-running
record failed_units systemctl --failed --no-legend --plain
record login_state loginctl show-user sl-management
record user_manager systemctl is-active "user@$(id -u sl-management).service"
record selinux_after getenforce
record rootless_info_after runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman info --format=json
record container_inspect_after runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman inspect sl-management-fixture
record fixture_log_after runuser -u sl-management -- env HOME=/var/lib/sl-management XDG_RUNTIME_DIR=/run/sl-management CONTAINERS_STORAGE_CONF=/etc/containers/storage-sl-management.conf CONTAINERS_CONF=/etc/containers/containers-sl-management.conf podman logs sl-management-fixture
record attack_systemctl_after_reboot runuser -u sl-management -- systemctl restart "$unit"
record journal journalctl -u "$unit" -b --no-pager
record audit journalctl -k -b -g 'avc:.*denied' --no-pager
finish
