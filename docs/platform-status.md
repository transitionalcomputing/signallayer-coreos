# Phase 3A read-only platform status

The status observation remains read-only. Administrative update and rollback
requests are separate bounded methods described in their lifecycle documents.

System D-Bus service and interface: `org.signallayer.Platform1`.
Object path: `/org/signallayer/Platform1`.
Method: `GetStatus() -> s`, containing a JSON object with `schema_version: "0.3"`.
Rust definitions and the client proxy are shared in `crates/protocol`.
`corectl status` formats this observation; `corectl status --json` emits it.
Neither client mode reconstructs status from guest files or backend commands.

The response contains:

- `product`, `version`, `platform_api_version`: installed image release fields.
- `source_revision`, `build_id`: installed metadata, or JSON null when missing
  or `unknown`. A dirty build uses a base revision with a dirty marker and a
  build ID derived from the recorded source-file manifest, not a false clean revision.
- `machine`: validated systemd machine ID, normalized running-kernel
  architecture, and current kernel boot ID. Missing or malformed authoritative
  values fail the request; no identity is synthesized.
- `network`: NetworkManager's documented global state and nullable primary
  connection. A primary connection contains one interface plus sorted,
  de-duplicated address/prefix and default-gateway strings. These properties
  come through a dedicated unprivileged observer whose bus policy permits only
  NetworkManager `Properties.Get`; they do not expose object paths, DNS, routes,
  MAC addresses, or secrets.
- `booted`: `deployment_id` (opaque), `image_reference`, `image_digest`.
  The daemon uses supported `bootc status --json`; on the current OSTree backend
  the opaque identifier combines observed checksum and deployment serial.
  Missing image identity represented by bootc as null remains null. Malformed
  or missing mandatory observations produce errors.
- `retained_rollback`: another deployment object or null, based solely on bootc's
  observed retained rollback target. This does not certify known-good status,
  authorize rollback, or assert a deployment acceptance policy.
- `update`: semantic update worker/staged state and reboot requirement.
- `rollback`: semantic rollback worker/queued state and reboot requirement.
  Bootc's `rollbackQueued` observation is authoritative; no separate state
  database exists.
- `health`: `state` (`healthy` or `degraded`), `system_state`, `failed_units`.
  Healthy means a valid booted deployment was observed, systemd's live
  `SystemState` is `running`, and `NFailedUnits` is zero. It makes no assertion
  about network reachability, applications, deployment acceptance, or security.
  Systemd properties and bootc status are sequential live observations, not an
  atomic snapshot. Unreadable health never becomes healthy.

Backend execution uses a fixed absolute executable and arguments, no shell,
15-second deadline, 64 KiB limits on each output stream, and kill/reap on timeout.
Only one observation is in flight; concurrent calls receive `Busy` rather than
starting unbounded privileged subprocesses. Health reads have a three-second
shared deadline. Network observation has a separate three-second deadline and
run concurrently with bootc status so the CLI's existing 25-second D-Bus method
deadline remains unchanged.

D-Bus errors use prefix `org.signallayer.Platform1.Error` with suffixes
`BackendUnavailable`, `BackendTimeout`, `InvalidBackendData`,
`MetadataUnavailable`, `MachineUnavailable`, `NetworkUnavailable`,
`HealthUnavailable`, `UpdateUnavailable`,
`RollbackUnavailable`, `Conflict`, or `Busy`. They contain concise
messages without backend output. Backend diagnostics go to the journal.
A failed CLI returns nonzero; human errors go to stderr, while `--json` emits
`{"error":{"code":"...","message":"..."}}` on stdout. A missing bus/service
is `ServiceUnavailable`; invalid responses use `InvalidResponse` or
`UnsupportedSchema`. Argument errors use `Usage`.

The image enables an ordinary `Type=dbus` systemd unit; there is no D-Bus
activation file. The policy allows any local user only the status method on
this service/object/interface; only root can own the service name. The daemon
runs as root because bootc host inspection requires administrative access to
system deployment state and explicitly requires `CAP_SYS_ADMIN` to enter its
private mount namespace, even for status. It also needs `CAP_SYS_PTRACE` to read
PID 1's mount-namespace link: a native boot with only `CAP_SYS_ADMIN` failed at
`/proc/1/ns/mnt`, and a disposable diagnostic boot with both capabilities
succeeded. Those are the two bounded capabilities; removing the capability set
produces a real `BackendUnavailable` error. The unit forbids privilege
escalation and uses private temporary storage, a read-only filesystem sandbox,
and protected home, kernel tunables and control groups. The daemon writes no
persistent application state. Bootc manages its own inspection/locking inside
its private namespace; runtime checks verify that global root/sysroot remain
read-only after the API calls.
Global SELinux enforcement and immutable-root settings remain inherited from
the pinned Fedora base. Phase 3B adds an image-owned dedicated enforcing
`sl_platformd_t` domain and automatic executable labeling, with supported bootc
children confined in that domain. Policy compilation/analysis and Rust tooling
remain outside the final runtime image. See [the hardening boundary and runtime
acceptance](platform-hardening.md) for the policy integration, permissions and
negative/recovery tests; a custom label alone is not acceptance evidence.

## Native validation

Build on the authorized Fedora x86_64 host with `podman build`, explicit
`SOURCE_REVISION` and `BUILD_ID`, and the checked-in Cargo.lock. The build stage
runs formatting, focused backend tests and the release build. Run native
`bootc container lint`, then `image/build/build-qcow2.sh` (which also performs
offline inspection). Preserve older disk and OCI artifacts.

Use `tests/boot/boot-qcow2.py DISK --phase3a --accel tcg --timeout 1800` with the
installed OVMF code/vars pair. This retains the original 18 Phase 2B checks and
adds daemon status, human/JSON output, comparison against independently observed
release and bootc identity, a transient DynamicUser client, missing-service and
missing-backend and removed-capability errors, and final restored service/system
health. DynamicUser output is read from journald, avoiding SELinux-denied FIFO
passing from the credential probe to PID 1. Backend failure
is injected by temporarily hiding bootc only in the daemon's systemd mount
namespace; no image binary or SELinux policy is changed. Test configuration
exists only in the disposable guest overlay. Serial, commands, journal and
machine evidence remain in ignored `image/build/output/`.

For Phase 4C, use `--phase4c --accel kvm --cpus 2 --timeout 1800` with the
same disk and OVMF arguments. This retains the Phase 4B checks and verifies
schema 0.3 against `/etc/machine-id`, kernel `uname` and boot ID, and direct
NetworkManager D-Bus properties. It also compares direct Platform, `corectl`,
and Session1 JSON, verifies deterministic network arrays, confirms Platform API
0.1 and the absence of `StartReboot`, and checks for related SELinux denials.
It also proves that `sl-network-observer` has a dedicated unprivileged identity,
no capabilities, a confined SELinux domain, and a system-bus policy that allows
NetworkManager `Properties.Get` while rejecting a representative mutation.
Loaded-policy analysis proves `sl_platformd_t` has no direct NetworkManager
message permission.
