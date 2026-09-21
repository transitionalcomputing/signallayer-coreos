# Phase 3D update activation

Phase 3D proves activation of an update staged through the fixed Phase 3C
path. Activation uses one normal graceful system reboot; it does not add a
reboot or rollback operation to the platform API.

The acceptance runner boots deployment A under KVM, stages a distinct B with
`corectl update`, and captures the authoritative `bootc status --format=json`
and product-facing `corectl status --json` results. It then invokes
`systemctl reboot` inside the guest and keeps the same QEMU process, disk
overlay, firmware variable store, and virtual hardware running through the
reboot.

After the machine returns, acceptance requires the exact staged B OSTree and
image identities to be booted, a changed boot ID, no staged deployment or
reboot requirement, and A to be retained as the rollback deployment. It also
rechecks systemd, `sl-platformd`, networking, SELinux enforcement, relevant
AVCs, composefs/read-only mounts, and rejected writes to `/` and `/usr`.

The test performs no rollback. Its disposable overlay is retained after clean
shutdown as a B-active/A-retained input for Phase 3E.
