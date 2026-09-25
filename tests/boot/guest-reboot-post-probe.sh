# Phase 4D BOOT_2 branch. The same credential-delivered probe runs on every
# boot of the one QEMU process; a recorded BOOT_1 boot_id selects this branch.
# Records use a post_ prefix so they never overwrite BOOT_1 evidence.
if [[ -e /var/lib/slprobe-4d/boot1_id ]]; then
    collect post_boot_id cat /proc/sys/kernel/random/boot_id
    collect post_previous_boot_id cat /var/lib/slprobe-4d/boot1_id
    collect post_system_state timeout 300 systemctl is-system-running --wait
    collect post_failed_units systemctl --failed --no-legend --plain
    collect post_selinux getenforce
    collect post_platform_status /usr/bin/corectl status --json
    collect post_session_status busctl --system --auto-start=no --json=short call org.signallayer.Session1 /org/signallayer/Session1 org.signallayer.Session1 GetPlatformStatus
    printf 'post_complete\t0\tZG9uZQ==\n' >&3
    echo 'CoreOS boot probe: post-reboot evidence collection complete'
    exit 0
fi
