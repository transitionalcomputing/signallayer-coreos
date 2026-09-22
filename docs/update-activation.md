# CoreOS 0.0.1 update activation

CoreOS 0.0.1 activation uses an update staged through the fixed update path.
The validated lifecycle uses one normal graceful system reboot; it does not add a
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

The activation acceptance test performs no rollback. Its disposable overlay was
retained after clean shutdown as the B-active/A-retained input for rollback
acceptance.
