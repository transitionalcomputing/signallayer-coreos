# Phase 4D extension, BOOT_1 only. Runs after the existing probes.
# The non-root StartReboot call is a UID/bus-policy authorization test: bus
# policy keyed by UID is the layer that restricts Platform methods for
# sl-sessiond. The fixture refuses to run as root.
reboot_boundary=$(cat <<'BOUNDARY_SOURCE'
__SL_REBOOT_BOUNDARY_SOURCE__
BOUNDARY_SOURCE
)
collect reboot_boot_id cat /proc/sys/kernel/random/boot_id
collect reboot_nonroot_denied runuser -u sl-sessiond -- /usr/bin/python3 -c "$reboot_boundary" start-reboot
collect reboot_pre_status /usr/bin/corectl status --json
# BOOT_2 identifies itself by finding this BOOT_1 boot_id on the per-run
# overlay. It is written only after all BOOT_1 evidence above is recorded.
collect reboot_marker sh -c 'install -d -m 0700 /var/lib/slprobe-4d && cat /proc/sys/kernel/random/boot_id > /var/lib/slprobe-4d/boot1_id && cat /var/lib/slprobe-4d/boot1_id'
