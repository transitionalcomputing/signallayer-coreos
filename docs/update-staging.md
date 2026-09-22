# CoreOS 0.0.1 update staging

CoreOS 0.0.1 stages the configured bootc image through this fixed path:

```text
corectl update
  -> org.signallayer.Platform1.StartUpdate()
  -> systemd StartUnit("sl-update.service", "fail")
  -> /usr/bin/bootc upgrade --quiet
```

`StartUpdate()` is root-only in the system-bus policy. `sl-platformd_t` can
start and query only the image-owned `sl-update.service` unit type. The daemon
uses a three-second systemd request deadline and returns after systemd has
registered the activation. The long-running pull and deployment operation
continues in the oneshot unit. A request made while that unit is active returns
`Busy`.

The unit contains no shell, variable command, caller-provided argument, or
caller-provided unit name. Its exact command is `bootc upgrade --quiet`.
`--apply` and `--download-only` are not used. Successful staging leaves the
running deployment and boot ID unchanged and queues the new deployment for the
next boot. CoreOS does not reboot automatically.

`corectl status` derives update state from the fixed systemd unit and fresh
`bootc status --json` output. Bootc remains authoritative for the booted and
staged deployment identities and the staged deployment's `downloadOnly` flag.
No separate persistent update database exists.

Bootc creates staged state with `O_TMPFILE`, before the eventual
`staged-deployment` basename exists. Systemd-tmpfiles deterministically labels
only `/run/ostree` as `sl_bootc_runtime_t`. Regular files created there by
Fedora's trusted `install_t` domain transition to `sl_bootc_state_t`, including
the anonymous inode that bootc later links as `staged-deployment`.
`sl-platformd_t` can search that directory and read only the dedicated state
type. It cannot list the directory or read generic `var_run_t` files. Bootc
also supports an externally provisioned `/run/ostree/auth.json`; because that
credential is not created by `install_t`, it does not receive the state type
and remains outside the daemon's read boundary.

## SELinux trust boundary

`sl-platformd_t` remains the confined API boundary. Fedora labels
`/usr/bin/bootc` as `install_exec_t` and provides the PID 1 transition to its
trusted `install_t` operating-system update domain. The dedicated unit invokes
bootc directly so this normal transition applies.

This is an explicit 0.0.1 design decision. A successful diagnostic staging run
under a dedicated permissive experiment produced 109,612 AVCs across 258 final
deployment types. Bootc and OSTree must create staged files with labels such as
`shadow_t`, `passwd_file_t`, `usr_t`, `lib_t`, `etc_t`, and
`systemd_unit_file_t`. SELinux type permissions are not limited to the staged
path, so granting that corpus to a custom worker would recreate installer-wide
authority while also authorizing equivalent live-system objects. The
experimental worker domain and launcher were therefore removed rather than
shipping a misleading confinement boundary.

Global SELinux enforcement remains enabled. The unit retains compatible
systemd restrictions and a bounded capability set. It intentionally omits
`NoNewPrivileges`, which prevents the Fedora domain transition, and
`RestrictSUIDSGID`, which was proven to make bootc's required
`openat2(RESOLVE_IN_ROOT)` return `ENOSYS`.

Automatic activation, reboot, rollback, scheduling, channels, and fleet
management are not included in CoreOS 0.0.1.
