# CoreOS 0.0.1 manual rollback

CoreOS 0.0.1 exposes explicit rollback selection through one fixed path:

```text
corectl rollback
  -> org.signallayer.Platform1.StartRollback()
  -> systemd StartUnit("sl-rollback.service", "fail")
  -> /usr/bin/bootc rollback
```

`StartRollback()` is root-only, bounded, and accepts no arguments. The fixed
oneshot unit contains no shell or caller-controlled command or unit name. It
does not use `--apply` or `--soft-reboot`, and it deliberately has no network
ordering dependency. Rollback selection and reboot remain separate operator
actions.

The daemon rejects a request when no retained deployment exists, an update or
rollback worker is active, an unapplied update is staged, or rollback is
already queued. Update and rollback starts share one short-lived mutation-start
permit. Bootc remains authoritative for the retained target and
`rollbackQueued`; no persistent SignalLayer rollback database exists.

Status schema `0.2` adds an independent `rollback` object with `idle`,
`running`, `queued`, or `failed` state, `reboot_required`, and structured
worker failure. `retained_rollback` continues to identify the target. Update
state remains independent.

Fedora's `install_exec_t` transition runs the exact worker in `install_t`.
The rollback unit reuses the published `sl_update_unit_file_t` label so the
older deployment can install it while staging the update. That label covers
only the two fixed SignalLayer deployment-mutation units; `sl_platformd_t`
receives no installer or generic systemd authority.

Bootc performs its normal `/etc` three-way deployment handling when changing
the selected deployment. CoreOS 0.0.1 does not add another configuration
persistence layer. Automatic rollback, health-triggered fallback, reboot,
boot-attempt policy, and deployment pinning are not included in CoreOS 0.0.1.
