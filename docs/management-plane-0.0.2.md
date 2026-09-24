# SignalLayer CoreOS 0.0.2 management-plane contract

**Status:** Phase 4A contract; Phase 4B validated
**Release:** SignalLayer CoreOS 0.0.2
**Platform API:** 0.2
**Status schema:** 0.3

## Purpose and release boundary

SignalLayer CoreOS 0.0.2 proves the first usable management layer above the
Platform API without weakening the 0.0.1 security model. The vertical slice is
a management consumer reading machine status through `sl-sessiond`, which uses
a shared Platform client and the existing system D-Bus boundary. The release
also adds one narrow privileged operation, controlled reboot.

SignalLayer CoreOS 0.0.1 already implements `GetStatus`, `StartUpdate`, and
`StartRollback`; `corectl status`, `update`, and `rollback`; fixed update and
rollback workers; immutable-root enforcement; and the confined
`sl-platformd` gatekeeper. The exact validated behavior remains documented in
[platform status](platform-status.md), [update staging](update-staging.md),
[update activation](update-activation.md), and [rollback](rollback.md).

The 0.0.2 work planned by this contract is:

- a reusable client for the local Platform D-Bus API;
- an unprivileged `sl-sessiond` foundation with one read-only upward status
  method;
- the minimum additional machine identity and network observations needed by a
  management consumer; and
- a root-authorized `StartReboot` Platform method with a fixed implementation.

Flavor lifecycle, a graphical or web console, provisioning, remote management,
and general power management remain deferred.

## Component ownership

| Component | Owns | Does not own |
| --- | --- | --- |
| `sl-platformd` | Platform authorization; machine observation; validation and dispatch of fixed privileged operations | User/session UX, flavor policy, arbitrary command or unit execution |
| `crates/platform-client` | System-bus connection, typed Platform calls, status decoding/version checks, and consistent client error mapping | Authorization, presentation, Linux inspection, retries or persistent state |
| `sl-sessiond` | The management-to-Platform read path and, later, flavor/session coordination | Machine mutation, deployment/network implementation, root authority, or duplicated platform state |
| `corectl` | Administrative CLI argument handling, output, exit status, and operator-facing confirmation | D-Bus plumbing, backend execution, or platform business logic |
| Management/UI consumers | Presentation and user workflow above `sl-sessiond` | Direct Linux/bootc/systemd/NetworkManager inspection or privileged machine control |

`sl-platformd` remains the sole privileged machine authority. `corectl` and
`sl-sessiond` are clients of the same contract; neither is an alternate
implementation.

## Trust and privilege model

`sl-platformd` continues to run as the constrained root service described in
[platform hardening](platform-hardening.md). System D-Bus policy authorizes
read-only status separately from each mutation. The broker admits
`StartUpdate`, `StartRollback`, and `StartReboot` only from root. The daemon
then validates state and selects a compile-time fixed unit name.

`sl-sessiond` runs as a dedicated unprivileged system user, with no Linux
capabilities and no membership in an administrative group. Its systemd service
may order itself after D-Bus and `sl-platformd`, but a temporary Platform API
failure must not prevent the machine from reaching its normal target. It calls
only the read-only Platform status method in 0.0.2. Its upward D-Bus policy
cannot confer mutation authority because `sl-sessiond` itself has none.

`sl-sessiond` must not execute privileged commands, invoke bootc, control
machine-mutation units, call reboot directly, change NetworkManager state,
scrape Linux files or commands for machine state, or acquire root for
convenience. A missing machine capability is addressed at the Platform API
boundary.

This preserves the 0.0.1 gatekeeper: every machine mutation still crosses the
root-only Platform API and resolves to a fixed mechanism selected by
`sl-platformd`.

## Shared Platform client contract

Phase 4B adds one workspace library at `crates/platform-client`, with package
name `sl-platform-client`. It depends on `sl-protocol`; the protocol crate
continues to own wire constants, serializable types, the generated proxy, and
Platform error names.

The client library owns:

- constructing the system-bus connection and Platform proxy;
- the existing 25-second client method deadline;
- initially, in Phase 4B, `get_status`, `start_update`, and `start_rollback`
  calls against Platform API 0.1;
- initially decoding and validating status schema 0.2 in Phase 4B, then status
  schema 0.3 in Phase 4C;
- `start_reboot` and Platform API 0.2 support when controlled reboot is added
  in Phase 4D; and
- converting transport, broker, remote-method, invalid-response, and
  unsupported-version failures into a small typed client error.

It must not inspect `/proc`, `/sys`, release files, systemd, bootc, or
NetworkManager; format CLI or UI output; authorize callers; run commands;
choose a systemd unit; retry mutations; or persist/cache machine state.

`corectl` moves its connection, proxy, status decoding, and D-Bus error mapping
into this crate while retaining CLI parsing and human/JSON presentation.
`sl-sessiond` uses the same client and calls only `get_status` in 0.0.2. This is
a focused local client, not a transport framework.

## `sl-sessiond` MVP contract

Phase 4B implements the workspace binary `sl-sessiond` and its systemd/D-Bus
packaging.

- **Identity:** dedicated unprivileged `sl-sessiond` system user; no
  capabilities or administrative group membership.
- **Lifecycle:** long-running systemd service, started at the normal system
  target after the system bus. It must recover from `sl-platformd` being
  temporarily unavailable without restarting the machine.
- **Platform relationship:** uses `sl-platform-client`; never talks to platform
  backends or machine primitives directly.
- **Owned state:** only process-local request/concurrency bookkeeping. No
  persistent database, cached authoritative status, or deployment state.
- **Upward interface:** system D-Bus service and interface
  `org.signallayer.Session1`, object `/org/signallayer/Session1`, with
  `GetPlatformStatus() -> s`. In Phase 4B the string contains existing status
  schema 0.2 JSON validated and reserialized by the shared client; Phase 4C
  upgrades this path to status schema 0.3. It is read-only and accepts no
  arguments.
- **Health/version:** successful name ownership and request handling are the
  service health signal. The daemon logs its package version at startup. The
  returned CoreOS/API versions come only from Platform status. If Platform
  status is unavailable or incompatible, the method returns a bounded
  structured D-Bus error rather than stale data.

The MVP does not discover or activate flavors, create user sessions, expose a
mutation API, or define a general session protocol. Those are later contracts.

## Platform status 0.3

Status schema 0.3 retains every 0.2 field and semantic unchanged. It adds two
required top-level objects:

```json
{
  "machine": {
    "machine_id": "opaque systemd machine ID",
    "architecture": "x86_64",
    "boot_id": "opaque kernel boot ID"
  },
  "network": {
    "state": "connected_global",
    "primary_connection": {
      "interface": "enp0s2",
      "addresses": ["192.0.2.10/24"],
      "default_gateways": ["192.0.2.1"]
    }
  }
}
```

`primary_connection` is nullable. `addresses` and `default_gateways` are
deterministically ordered strings and may be empty. Address strings include
their prefix length. No MAC address, SSID, DNS configuration, route table,
secret, or NetworkManager object path is exposed.

`network.state` is one of `unknown`, `disconnected`, `connecting`,
`connected_local`, `connected_site`, or `connected_global`, mapped directly
from NetworkManager's documented global state. The primary connection,
interface, IP address data, and gateways come from NetworkManager D-Bus
properties. Observation is read-only; no `nmcli` subprocess or configuration
mutation is permitted.

The complete 0.0.2 management facts are represented as follows:

- product version, Platform API version, source revision, and build ID: existing
  release fields;
- machine identity, architecture, and current boot identity: `machine`;
- running deployment: existing `booted`;
- staged deployment and activation requirement: existing `update.staged` and
  `update.reboot_required`;
- rollback availability: existing `retained_rollback != null`, subject to the
  existing conflict rules;
- update/rollback lifecycle: existing `update` and `rollback`; and
- basic network state: `network`.

No redundant `rollback_available`, `next_deployment`, or custom lifecycle
database is added.

## API and schema versioning

Implementation advances in this fixed sequence:

- Phase 4B uses **Platform API 0.1** and **status schema 0.2** through the new
  shared-client and sessiond architecture. No version changes occur.
- Phase 4C retains **Platform API 0.1** and adds **status schema 0.3** with the
  required `machine` and `network` fields.
- Phase 4D adds `StartReboot`, advances to **Platform API 0.2**, and retains
  **status schema 0.3**.

The final released 0.0.2 image therefore reports **Platform API 0.2** and
**status schema 0.3**.

Platform API 0.2 is an additive evolution: `GetStatus`, `StartUpdate`, and
`StartRollback` retain their exact signatures and behavior, while
`StartReboot` is added. A caller must not assume the new method exists when the
reported Platform API version is below 0.2.

Status 0.3 is the 0.2 object plus required `machine` and `network` fields. It is
versioned separately because 0.0.1 clients intentionally require an exact
schema and reject unknown fields. The Phase 4B shared client accepts schema
0.2; Phase 4C updates it to accept schema 0.3. It does not silently reinterpret
0.2 as complete 0.3 management status. This explicit incompatibility prevents
absent identity/network facts from being presented as valid observations.

## Controlled reboot contract

Platform API 0.2 adds exactly:

```text
StartReboot() -> ()
```

The method takes no arguments and is root-only under system D-Bus policy. A
successful return means systemd accepted the fixed reboot worker start request;
it does not mean the machine has completed rebooting, nor does it guarantee the
reply reaches a caller before shutdown begins.

`sl-platformd` may start and query only the image-owned
`sl-reboot.service`. The unit has a dedicated SELinux unit-file type and one
fixed, non-shell command:

```text
/usr/bin/systemctl --no-block reboot
```

There is no caller-selected unit, action, delay, reason, deployment, command,
or argument. No shutdown, suspend, hibernate, restart-unit, or generic power
method is added.

If the update or rollback worker is active, `StartReboot` returns `Conflict`
and does not interrupt it. If the fixed reboot worker is already active, the
method returns `Busy`. Failure to inspect or start the exact unit returns
`RebootUnavailable`. Otherwise the request is accepted once by systemd.

Reboot owns no deployment policy. A staged update or queued rollback is allowed
when no mutation worker is active; bootc/systemd's already-recorded next-boot
selection remains authoritative. `StartReboot` neither stages an update,
selects rollback, changes boot state, nor retries automatically.

## State and source-of-truth matrix

| Field or operation | Authority | Platform behavior |
| --- | --- | --- |
| Product/API/source/build identity | `/usr/lib/signallayer/release` in the booted image | Read and validate fixed keys |
| Machine identity | systemd `/etc/machine-id` | Return opaque validated ID |
| Architecture | running kernel `uname` machine value | Return normalized architecture string |
| Boot identity | kernel boot ID | Return opaque validated ID |
| Booted/staged/retained deployments | `bootc status --json` / OSTree | Preserve existing derived semantic model |
| Update state | fixed update unit plus bootc staged state | Preserve existing state derivation |
| Rollback state | fixed rollback unit plus bootc rollback state | Preserve existing state derivation |
| System health | systemd manager state and failed-unit count | Preserve existing health semantics |
| Basic network state | NetworkManager D-Bus | Read global and primary-connection properties only |
| Reboot authorization | system D-Bus policy | Root-only exact method |
| Reboot execution | systemd and fixed `sl-reboot.service` | Start/query exact unit only |
| sessiond availability | systemd service state / D-Bus name ownership | No custom persisted health state |

All observations are bounded live reads and need not be an atomic cross-service
snapshot. No new persistent state database or cache is introduced.

## Error and authorization semantics

The shared client exposes this small semantic model while retaining the remote
error code/message for diagnostics:

| Outcome | Wire/source behavior | Client meaning |
| --- | --- | --- |
| Success | Normal method reply | Requested observation or accepted operation |
| Unauthorized | Broker `AccessDenied` | Caller lacks permission; do not retry as another operation |
| Unsupported | API version mismatch or `UnknownMethod` | Capability is absent on this platform version |
| Invalid request | D-Bus `InvalidArgs` | Method shape is invalid; zero-argument checks remain strict |
| Busy | `org.signallayer.Platform1.Error.Busy` | Same bounded operation/start path is active |
| Conflict | `org.signallayer.Platform1.Error.Conflict` | Current lifecycle state forbids the request |
| Platform failure | Existing bounded Platform errors, plus `RebootUnavailable` | Authoritative subsystem could not satisfy the request |
| Invalid response | Decode/schema/validation failure | Never present malformed data as status |

`sl-sessiond` maps shared-client failures to concise
`org.signallayer.Session1.Error.*` errors without backend output. It does not
hide authorization failures, retry mutations, or invent fallback data.

## Phase handoff criteria

### 4B — shared client and sessiond foundation

**Validated:** the shared client, refactored `corectl`, confined unprivileged
`sl-sessiond`, and read-only Session1 status path passed unit, policy, image,
and KVM checks while retaining Platform API 0.1 and status schema 0.2.

- Add `sl-platform-client`, move corectl's D-Bus/status/error mechanics into it,
  and preserve existing CLI behavior and deadlines using Platform API 0.1 and
  status schema 0.2. Its initial calls are `get_status`, `start_update`, and
  `start_rollback`; it does not provide `start_reboot`.
- Add an unprivileged systemd-managed `sl-sessiond` that owns only
  `org.signallayer.Session1` and implements bounded `GetPlatformStatus` through
  the shared client using existing status schema 0.2.
- Prove neither consumer invokes machine backends or gains mutation authority;
  no persistence is added and no API or schema version changes occur.

### 4C — management/status surface

- Implement status schema 0.3 while Platform API remains at 0.1; do not add
  `StartReboot`.
- Populate `machine` from systemd/kernel identity and `network` from
  NetworkManager D-Bus, with bounded reads and validation.
- Update `sl-platform-client`, corectl, and `sl-sessiond` to consume schema 0.3,
  and prove their observations agree for all old fields and the new management
  fields, including degraded/unavailable paths.
- Preserve all 0.0.1 status, confinement, immutable-root, update, and rollback
  behavior.

### 4D — controlled reboot

- Add zero-argument `StartReboot`, root-only bus policy, the compile-time fixed
  unit name, dedicated unit-file label, and the exact fixed command above; at
  this phase advance Platform API from 0.1 to 0.2 while status remains 0.3.
- Add `start_reboot` to `sl-platform-client` and `corectl reboot`; do not grant
  `sl-sessiond` the method.
- Prove prompt acceptance, Busy/Conflict/failure behavior, exact unit/command,
  no arbitrary parameters, and one orderly reboot into bootc's preselected
  deployment without changing update/rollback policy.

## Explicit non-goals and deferred work

0.0.2 does not design or implement an installer, provisioning UI, graphical
desktop, CloudOS, JumpOS, full web console, remote fleet management, production
registry architecture, automatic or health-triggered rollback, recovery
environment, storage or partitioning APIs, encryption UX, Wi-Fi/VPN/DNS/route
or firewall management, TPM enrollment, Secure Boot, GPU management, plugins,
arbitrary command execution, shell/SSH provisioning, package management,
flavors, signing infrastructure, future GUI design, shutdown, suspend,
hibernate, or a broad power API.

Full flavor discovery and session lifecycle are deferred until a separate
contract establishes their state and trust model.

## Minimal implementation map for 4B–4D

- `Cargo.toml`, `Cargo.lock`: add the focused client crate and sessiond binary.
- `crates/platform-client/`: shared typed Platform client for existing API 0.1
  and schema 0.2 in 4B; add schema 0.3 handling in 4C and `start_reboot` with
  API 0.2 in 4D.
- `crates/protocol/`: add schema 0.3 types in 4C; add the Platform API 0.2 proxy
  method and reboot error in 4D.
- `corectl/`: consume the client in 4B, consume schema 0.3 in 4C, and add
  `reboot` presentation in 4D.
- `sessiond/`: unprivileged daemon and read-only upward interface.
- `platformd/`: machine/network observations and fixed reboot dispatch.
- `image/platform/`: sessiond packaging and policy; root-only `StartReboot`;
  fixed reboot unit and narrow SELinux labels/permissions.
- `docs/platform-status.md` and focused lifecycle/security docs: update only as
  each implemented phase becomes validated behavior.
- existing Rust/static/boot harnesses: extend by phase for client equivalence,
  read-only management state, authorization, confinement, and controlled
  reboot acceptance.

No implementation phase should add a second privileged daemon, a custom
machine-state database, or a path around `sl-platformd`.
