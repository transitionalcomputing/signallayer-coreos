# Phase 3A extension, appended to the credential probe before its completion
# marker. All mutations are transient unit configuration in the disposable VM.
collect platform_active systemctl is-active sl-platformd.service
collect platform_unit systemctl show sl-platformd.service --property=User,CapabilityBoundingSet,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp
collect platform_process ps --no-headers -o user,pid,label,args -C sl-platformd
collect platform_human /usr/bin/corectl status
collect platform_json /usr/bin/corectl status --json

# PID 1 cannot write the credential probe's initrc_t-labelled output FIFO.
# Use its normal journal streams instead of passing the probe pipe with --pipe.
collect platform_unprivileged_backend_start systemd-run --quiet --wait --collect --unit=slprobe-unpriv-backend --property=DynamicUser=yes --property=StandardOutput=journal --property=StandardError=journal /usr/bin/bootc status --json
collect platform_unprivileged_backend journalctl --boot --quiet --no-pager --output=cat --unit=slprobe-unpriv-backend.service _COMM=bootc
collect platform_unprivileged_uid_start systemd-run --quiet --wait --collect --unit=slprobe-unpriv-uid --property=DynamicUser=yes --property=StandardOutput=journal --property=StandardError=journal /usr/bin/id -u
collect platform_unprivileged_uid journalctl --boot --quiet --no-pager --output=cat --unit=slprobe-unpriv-uid.service _COMM=id
collect platform_unprivileged_json_start systemd-run --quiet --wait --collect --unit=slprobe-unpriv-json --property=DynamicUser=yes --property=StandardOutput=journal --property=StandardError=journal /usr/bin/corectl status --json
collect platform_unprivileged_json journalctl --boot --quiet --no-pager --output=cat --unit=slprobe-unpriv-json.service _COMM=corectl
collect platform_unprivileged_json_metadata journalctl --boot --quiet --no-pager --output=json --unit=slprobe-unpriv-json.service _COMM=corectl

platform_dropin=/run/systemd/system/sl-platformd.service.d/90-boot-test.conf
restore_platform() {
    rm -f "$platform_dropin"
    systemctl daemon-reload
    systemctl start sl-platformd.service
}
trap restore_platform EXIT
collect platform_stop systemctl stop sl-platformd.service
collect platform_service_error /usr/bin/corectl status --json
collect platform_restart systemctl start sl-platformd.service

# Hide only the backend executable in this service's mount namespace; this
# exercises a real daemon error without changing the image or SELinux policy.
mkdir -p "${platform_dropin%/*}"
printf '[Service]\nInaccessiblePaths=/usr/bin/bootc\n' >"$platform_dropin"
collect platform_test_reload systemctl daemon-reload
collect platform_backend_restart systemctl restart sl-platformd.service
collect platform_backend_error /usr/bin/corectl status --json
# Reduce the daemon's capability set for a second real backend failure, then
# restore the image-owned requirement before collecting final healthy state.
printf '[Service]\nCapabilityBoundingSet=\n' >"$platform_dropin"
collect platform_capability_reload systemctl daemon-reload
collect platform_capability_restart systemctl restart sl-platformd.service
collect platform_capability_error /usr/bin/corectl status --json
rm -f "$platform_dropin"
collect platform_restore_reload systemctl daemon-reload
collect platform_restore_restart systemctl restart sl-platformd.service
collect platform_final_active systemctl is-active sl-platformd.service
collect platform_final_json /usr/bin/corectl status --json
collect platform_final_mounts findmnt --json --output TARGET,SOURCE,FSTYPE,OPTIONS
collect platform_final_root_write write_probe "/.slprobe-final-$marker"
collect platform_final_usr_write write_probe "/usr/.slprobe-final-$marker"
collect platform_final_system_state systemctl is-system-running
collect platform_final_failed_units systemctl --failed --no-legend --plain
collect platform_journal journalctl --boot --no-pager --unit sl-platformd.service
collect platform_final_boot_journal journalctl --boot --no-pager --lines=800
trap - EXIT
