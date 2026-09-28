# Local appliance console (0.0.3)

`sl-console` is the trusted local SignalLayer appliance interface. It owns
tty1 and the image's configured `ttyS0` serial console. It is not a Linux
login, shell, terminal, or general administration interface.

## Authority

The console reads authoritative status from Session1 schema 0.4. It uses
Auth1 for `VerifyPassword` and `RecoverPassword`; it stores no credential and
implements no password hashing. Its Platform1 authority is exactly:

- `EnableRemoteManagement`
- `DisableRemoteManagement`
- `ReenrollRemoteManagement`
- `GetRemoteManagementEnrollment`

It has no update, rollback, reboot, command-execution, systemctl, package, or
filesystem administration path.

Before enrollment, the trusted console may enable remote management and show
the pairing code without a credential. Once enrolled, lifecycle actions
require a successful Auth1 password check. Recovery uses Auth1 and the
operator's recovery key. `ResetIncomplete` is displayed as a distinct repair
state whose action is Reenroll.

The password check is enforced by the console UI. Platform authorizes the
console service identity for its four methods; it does not consume an Auth1
proof. This accepted 0.0.3 boundary is documented in the frozen remote
management contract.

## Terminal ownership and failure

`sl-console@.service` runs as the dedicated `sl-console` user on two explicit
instances: `tty1` and `ttyS0`. systemd opens the configured terminal and passes
it as the process's standard input and output. The service always restarts.
The service cannot use `PrivateDevices=yes`, because that would hide these
physical terminals before systemd establishes standard input. SELinux still
limits `sl_console_t` to the terminal descriptors inherited from systemd.
The generic getty, serial-getty, and console-getty templates are masked in the
image, so a console crash cannot reveal a Linux login prompt.

The console is ordered after and wants the fixed boot-reset worker, but does
not require that worker to succeed. A failed reset can therefore leave
`reset-pending` while the appliance console still starts and presents Reenroll
as the repair path.

The SELinux `sl_console_t` domain can use inherited terminal descriptors and
exchange D-Bus messages with Auth1, Platform1, and Session1. It receives no
capabilities or network socket access. Broker policy continues to enforce the
exact Auth1 and Platform1 caller matrices.

Runtime verification of TTY ownership, restart behavior, installed SELinux
behavior, and cross-service workflows belongs to Phase 5E.
