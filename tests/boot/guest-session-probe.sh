# Phase 4B extension. It exercises only the read-only Session1 path and the
# existing broker authorization boundary; no update or rollback is started.
collect session_platform_active systemctl is-active sl-platformd.service
collect session_active systemctl is-active sl-sessiond.service
collect session_unit systemctl show sl-sessiond.service --property=User,Group,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges,PrivateDevices,PrivateTmp,ProtectSystem,ProtectHome,RestrictAddressFamilies,FragmentPath,ExecStart
collect session_identity id sl-sessiond
collect session_process ps --no-headers -o user:32=,label=,args= -C sl-sessiond
collect session_process_status sh -c 'pid=$(systemctl show --property=MainPID --value sl-sessiond.service); cat "/proc/$pid/status"'
collect session_owner busctl --system --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s org.signallayer.Session1
collect session_introspection busctl --system --auto-start=no introspect org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1
collect session_platform_status /usr/bin/corectl status --json
collect session_status busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
collect session_unprivileged_status runuser -u sl-sessiond -- busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
collect session_update_denied runuser -u sl-sessiond -- busctl --system --auto-start=no call org.signallayer.Platform1 /org/signallayer/Platform1 org.signallayer.Platform1 StartUpdate
collect session_rollback_denied runuser -u sl-sessiond -- busctl --system --auto-start=no call org.signallayer.Platform1 /org/signallayer/Platform1 org.signallayer.Platform1 StartRollback

collect session_platform_stop systemctl stop sl-platformd.service
collect session_unavailable busctl --system --auto-start=no call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
collect session_active_during_platform_failure systemctl is-active sl-sessiond.service
# Earlier failure-path checks deliberately restart Platform enough times to
# reach systemd's start throttle on fast KVM hosts. Clear only that test-created
# counter before proving the existing Session recovery path.
collect session_platform_reset_failed systemctl reset-failed sl-platformd.service
collect session_platform_restart systemctl start sl-platformd.service
collect session_recovered_status busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
collect session_final_system_state systemctl is-system-running
collect session_final_failed_units systemctl --failed --no-legend --plain
collect session_audit journalctl --boot --no-pager --output=cat _TRANSPORT=audit
collect session_journal journalctl --boot --no-pager --unit sl-sessiond.service
