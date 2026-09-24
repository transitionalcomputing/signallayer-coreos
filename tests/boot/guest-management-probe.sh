# Phase 4C extension. Compare every new Platform fact with its authoritative
# local source. The unprivileged observer is separately checked below.
collect management_machine_id cat /etc/machine-id
collect management_architecture uname -m
collect management_boot_id cat /proc/sys/kernel/random/boot_id
collect management_platform_status busctl --system --auto-start=no --json=short call org.signallayer.Platform1 /org/signallayer/Platform1 org.signallayer.Platform1 GetStatus
collect management_platform_introspection busctl --system --auto-start=no introspect org.signallayer.Platform1 /org/signallayer/Platform1 org.signallayer.Platform1

networkmanager_reference() {
    local primary_raw primary devices_raw device ip4_raw ip4 ip6_raw ip6
    printf 'state='
    busctl --system --auto-start=no get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager State
    primary_raw=$(busctl --system --auto-start=no get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager PrimaryConnection) || return
    printf 'primary=%s\n' "$primary_raw"
    read -r _ primary <<<"$primary_raw"
    primary=${primary#\"}
    primary=${primary%\"}
    [[ $primary != / ]] || return 0

    devices_raw=$(busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$primary" org.freedesktop.NetworkManager.Connection.Active Devices) || return
    printf 'devices=%s\n' "$devices_raw"
    read -r _ _ device _ <<<"$devices_raw"
    device=${device#\"}
    device=${device%\"}
    [[ -n $device ]] || return 1
    printf 'interface='
    busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$device" org.freedesktop.NetworkManager.Device Interface
    printf 'default4='
    busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$primary" org.freedesktop.NetworkManager.Connection.Active Default
    printf 'default6='
    busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$primary" org.freedesktop.NetworkManager.Connection.Active Default6

    ip4_raw=$(busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$primary" org.freedesktop.NetworkManager.Connection.Active Ip4Config) || return
    printf 'ip4=%s\n' "$ip4_raw"
    read -r _ ip4 <<<"$ip4_raw"
    ip4=${ip4#\"}
    ip4=${ip4%\"}
    if [[ $ip4 != / ]]; then
        printf 'ip4_addresses='
        busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$ip4" org.freedesktop.NetworkManager.IP4Config AddressData
        printf 'ip4_gateway='
        busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$ip4" org.freedesktop.NetworkManager.IP4Config Gateway
    fi

    ip6_raw=$(busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$primary" org.freedesktop.NetworkManager.Connection.Active Ip6Config) || return
    printf 'ip6=%s\n' "$ip6_raw"
    read -r _ ip6 <<<"$ip6_raw"
    ip6=${ip6#\"}
    ip6=${ip6%\"}
    if [[ $ip6 != / ]]; then
        printf 'ip6_addresses='
        busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$ip6" org.freedesktop.NetworkManager.IP6Config AddressData
        printf 'ip6_gateway='
        busctl --system --auto-start=no get-property org.freedesktop.NetworkManager "$ip6" org.freedesktop.NetworkManager.IP6Config Gateway
    fi
}
collect management_networkmanager_reference networkmanager_reference
collect management_observer_unit systemctl show sl-network-observer.service --property=MainPID,ActiveState,SubState,User,Group,ExecStart,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges
collect management_observer_identity getent passwd sl-network-observer
collect management_observer_groups id sl-network-observer
observer_pid=$(systemctl show --value --property=MainPID sl-network-observer.service)
collect management_observer_process ps --no-headers -o pid,user:32,label,args -p "$observer_pid"
collect management_observer_capabilities sh -c 'grep "^Cap\(Inh\|Prm\|Eff\|Bnd\|Amb\):" "/proc/$1/status"' sl-observer "$observer_pid"
collect management_observer_status runuser -u sl-network-observer -- busctl --system --auto-start=no --json=short call org.signallayer.NetworkObserver1 /org/signallayer/NetworkObserver1 org.signallayer.NetworkObserver1 GetNetworkStatus
collect management_observer_nm_read runuser -u sl-network-observer -- busctl --system --auto-start=no get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager State
# Setting the already-true networking property is harmless even if a boundary
# regresses, but the broker must reject the request before it reaches NM.
collect management_observer_nm_set_denied runuser -u sl-network-observer -- busctl --system --auto-start=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.DBus.Properties Set ssv org.freedesktop.NetworkManager NetworkingEnabled b true
# A mutation-shaped request is rejected by dbus-broker before NetworkManager
# sees it. Reload mode 0 would otherwise be a real operation, so failure is
# required and no retry is attempted.
collect management_observer_nm_mutation_denied runuser -u sl-network-observer -- busctl --system --auto-start=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Reload u 0
collect management_observer_bus_config cat /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf
collect management_loaded_policy sh -c 'gzip -c /sys/fs/selinux/policy | base64 --wrap=0'
collect management_loaded_policy_hash sha256sum /sys/fs/selinux/policy
collect management_audit journalctl --boot --no-pager --output=cat _TRANSPORT=audit
