# Phase 4C extension. Compare every new Platform fact with its authoritative
# local source. NetworkManager properties are observed directly over D-Bus.
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
collect management_audit journalctl --boot --no-pager --output=cat _TRANSPORT=audit
