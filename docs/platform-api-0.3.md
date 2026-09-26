# Platform API 0.3: remote-management lifecycle (0.0.3)

**Status:** 5C-b step 1 draft, for review. Derived from the frozen
[0.0.3 remote management contract](remote-management-0.0.3.md) and the frozen
[sl-authd interface](authd-interface-0.0.3.md). It changes no frozen decision.

Labels used below:
- **Proposal:** a value or mechanism chosen here, open for review.
- **Interpretation (review):** a place where the contract had to be read to
  reach a design. Each one is also listed at the end.

## Scope and principles

- Platform API 0.3 adds exactly four fixed, zero-argument methods to
  `org.signallayer.Platform1`. The existing methods (`GetStatus`,
  `StartUpdate`, `StartRollback`, `StartReboot`) are unchanged.
  `PLATFORM_API_VERSION` in `/usr/lib/signallayer/release` becomes `0.3`.
- sl-platformd remains the sole machine-mutation authority. It stays
  `ProtectSystem=strict` with no writable paths, as today. Every filesystem
  change is made by a fixed worker unit it starts, and every authentication
  change by a fixed sl-authd method it calls.
- Platform never reads or writes sl-authd's files, and sl-authd never learns
  the URL, the addresses or the TLS identity.
- No method creates or regenerates a credential except as the contract states:
  - Enable creates a pairing only when no operator is enrolled, and a TLS
    identity only when none exists;
  - Reenroll rotates the TLS identity and creates a fresh pairing.

## Existing machinery this builds on

- **Fixed worker units** (`sl-update`, `sl-rollback`, `sl-reboot`) are started
  by `start_worker`:
  - it loads the unit, returns `Busy` if it is not `inactive` or `failed`,
    then calls `StartUnit(name, "fail")`;
  - it waits only until the unit leaves its idle state or its `InvocationID`
    changes;
  - it does not wait for the worker to finish.
- **`mutation_starts`** is a one-permit semaphore, taken with `try_acquire`
  (`Busy` if held) by `StartUpdate`, `StartRollback` and `StartReboot`, and held
  for the whole evaluation.
- **`CheckedPlatform`** rejects any argument to the zero-argument methods with
  `InvalidArgs` before dispatch.
- **Errors** are `org.signallayer.Platform1.Error.*`, with fixed messages that
  never include backend output.
- **Bus policy:** the default context allows `GetStatus` and explicitly denies
  each mutating member; `<policy user="root">` allows each mutating member by
  exact destination, path, interface and member.
- **SELinux:** sl_platformd_t may `start` and `status` only its own
  unit-file types (`sl_update_unit_file_t`, `sl_reboot_unit_file_t`).

## Components added in 5C-b (names are proposals)

| Unit or file | Purpose |
|---|---|
| `sl-managementd.service` | The HTTPS server. Unprivileged, no capabilities. Static `WantedBy=multi-user.target` with `ConditionPathExists=` on the enabled marker and on `tls/current` (see below). |
| `sl-rm-enable.service` | Oneshot worker: ensure a TLS identity exists (generate only if absent), then durably create the enabled marker. |
| `sl-rm-disable.service` | Oneshot worker: durably remove the enabled marker. |
| `sl-rm-rotate.service` | Oneshot worker: generate a new TLS identity and atomically replace the current one. |
| `sl-rm-boot-reset.service` | Oneshot early-boot worker: the boot-time reset. |
| `/usr/libexec/signallayer/sl-remote-worker` | One Rust binary for the four worker units. Each unit's `ExecStart=` is a fixed argv selecting one fixed mode (`enable`, `disable`, `rotate-tls`, `boot-reset`). It takes no other input, runs no shell, and runs `/usr/bin/openssl` only with the fixed argv lists below. |

Platform needs one new helper beside `start_worker`: `run_worker`.
- It starts a oneshot worker the same way, then waits, within a bounded
  timeout, for that invocation to finish.
- It succeeds only if the unit returns to `inactive` with
  `Result=success`.
- Any other outcome is `RemoteManagementUnavailable`.
- **Proposal:** a worker timeout of 30 seconds, and 10 seconds for starting
  or stopping sl-managementd.

## Methods

All four are zero-argument. `CheckedPlatform`'s `ZERO_ARGUMENT_METHODS` gains
them, so an argument is rejected with `InvalidArgs` before any permit is taken
or state is read.

### New errors
| Error | Meaning |
|---|---|
| `RemoteManagementUnavailable` | A fixed worker, sl-managementd, or remote-management state could not be controlled or read. |
| `AuthUnavailable` | An sl-authd call failed. The sl-authd error name is not passed through, and the message is fixed. |

`Busy` and `NetworkUnavailable` are reused with their existing meaning.

### EnableRemoteManagement() -> ()
**Steps:**
1. Take the remote-management permit, or return `Busy`.
2. `run_worker(sl-rm-enable.service)`:
   1. if no TLS identity exists, generate one; an existing identity is never
      rotated;
   2. durably create the enabled marker. **This is the commit point for
      `enabled`.**
3. Call `Auth1.EnsurePendingPairing`. This creates a pairing only when no
   operator is enrolled and no unexpired pairing exists, and never rotates a
   code.
4. `StartUnit(sl-managementd.service, "fail")` if it is not active, and wait
   until it is active.

**Errors:** `Busy`, `RemoteManagementUnavailable`, `AuthUnavailable`.

**Idempotency:** on a fully enabled machine every step is a no-op. If the
previous pairing expired and no operator is enrolled, step 3 creates a new one,
as the contract requires. The TLS identity is never rotated.

### DisableRemoteManagement() -> ()
**Steps:**
1. Take the permit, or return `Busy`.
2. `run_worker(sl-rm-disable.service)`: durably remove the enabled marker.
   **This is the commit point for `enabled`.** From here on, sl-managementd
   cannot be started at boot, because its condition fails.
3. `StopUnit(sl-managementd.service, "replace")`, and wait until it is
   inactive. All web sessions end with the process.
4. Call `Auth1.CancelPendingPairing`.

Enrollment and the TLS identity are preserved.

**Errors:** `Busy`, `RemoteManagementUnavailable`, `AuthUnavailable`.

**Idempotency:** on a disabled machine every step is a no-op.

**Interpretation (review):** web sessions are held only in sl-managementd's
memory, so stopping it invalidates them all. The contract says
sl-managementd owns sessions, but not where they are stored.

### ReenrollRemoteManagement() -> ()
**Steps:**
1. Take the permit, or return `Busy`.
2. `StopUnit(sl-managementd.service)`, and wait until it is inactive. This
   ends all sessions and closes the login and pairing path before the
   credential changes.
3. Call `Auth1.ResetEnrollment`. **This is the commit point for invalidating
   the old credential.** It also clears any pairing and all sl-authd backoff
   counters.
4. `run_worker(sl-rm-rotate.service)`: a new identity is atomically swapped
   in. **This is the commit point for the TLS rotation.**
5. Call `Auth1.EnsurePendingPairing`, which creates a fresh pairing.
6. If the enabled marker exists, `StartUnit(sl-managementd.service)`.

**Errors:** `Busy`, `RemoteManagementUnavailable`, `AuthUnavailable`.

**Order rationale:** the credential is reset before the TLS identity is rotated.
A failure between the two therefore leaves the old credential invalid, not the
old credential valid behind a new fingerprint. sl-managementd is started only
after every earlier step succeeded, so it never serves an unenrolled machine
with a stale identity as the result of this call.

**Interpretation (review):** Reenroll does not change `enabled`. On a disabled
machine it still resets, rotates and creates a pairing, as the contract lists,
but does not start sl-managementd. The pairing then expires unused unless the
owner enables remote management within 10 minutes. The alternative is to have
Reenroll require, or imply, Enable.

### GetRemoteManagementEnrollment() -> (s url, s fingerprint, s pairing_code, t expires_at)
**Steps:**
1. Take the permit, or return `Busy`. The permit is used so the result is never
   a mixture from before and after a concurrent mutation.
2. **URL:** from the network observer's primary connection (see "Network
   endpoint"). An empty string if there is no eligible address.
3. **Fingerprint:** from `tls/current/fingerprint`, validated against the
   canonical format. An empty string if no identity exists.
4. **Pairing:** from `Auth1.GetPendingPairing`. `pairing_code` is the 8
   canonical characters and `expires_at` is Unix seconds. They are `""` and `0`
   when no pairing is pending.

**Errors:** `Busy`, `NetworkUnavailable` (the observer failed),
`RemoteManagementUnavailable` (an identity exists but its fingerprint is
unreadable or malformed), `AuthUnavailable`.

**Never:** it never creates, extends or regenerates a pairing or TLS identity,
and it never reads the private key.

**Formatting:** the console displays the code as `XXXX-XXXX`; Platform returns
it unformatted, as sl-authd does.

**Interpretation (review):** the contract lists `pairing_code` and
`expires_at` as "present only while a pairing is pending". This is expressed
with a fixed `(ssst)` signature and empty/zero values, not optional types.

## Postcondition and failure matrices

Columns give the state after the failure. "Unchanged" means as before the call.

### Enable
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | Retry |
|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | Retry Enable. |
| 2.1 identity generation | unchanged | unchanged | unchanged | unchanged (nothing is swapped in on failure) | unchanged | Retry Enable. |
| 2.2 marker write | unchanged | unchanged | unchanged | present (possibly just generated; never rotated later by Enable) | unchanged | Retry Enable; 2.1 is then a no-op. |
| 3 sl-authd | **true** | unchanged | unchanged | present | unchanged | Retry Enable; 2 is a no-op. |
| 4 start sl-managementd | true | false | unchanged | present | pending if unenrolled | Retry Enable: the pairing is not rotated while unexpired. At the next boot the service also starts, because the marker and identity exist. |

### Disable
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | Retry |
|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | Retry. |
| 2 marker removal | unchanged | unchanged | unchanged | unchanged | unchanged | Retry Disable. |
| 3 stop sl-managementd | **false** | possibly true | unchanged | unchanged | unchanged | Retry Disable. Status shows the inconsistency (`enabled` false, `listening` true) rather than hiding it. A reboot also ends it, because the service's condition now fails. |
| 4 cancel pairing | false | false | unchanged | unchanged | may remain pending until it expires (at most 10 minutes); unreachable because nothing listens | Retry Disable. |

### Reenroll
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | Retry |
|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | Retry. |
| 2 stop sl-managementd | unchanged | unknown; status shows it | unchanged | unchanged | unchanged | Retry Reenroll. |
| 3 sl-authd reset | unchanged | false | unchanged | unchanged | unchanged | Retry Reenroll. Until then, or at the next boot, the machine is as before the call. |
| 4 rotation | unchanged | false | **false** | old identity (no partial identity) | none | Retry Reenroll (the reset repeats harmlessly). A reboot before the retry starts sl-managementd with the old identity, unenrolled and with no pairing: nobody can pair until a local Enable or Reenroll. |
| 5 pairing | unchanged | false | false | **new** | none | Retry Reenroll (rotates again; nothing is enrolled), or Enable (creates a pairing without rotating, and starts the service). |
| 6 start sl-managementd | true | false | false | new | pending | Retry Enable, or Reenroll. |

**General rules:**
- Every step is individually durable or memory-only, and idempotent. A crash
  or reboot at any point is equivalent to a failure at that step.
- No failure leaves a partially written marker or TLS identity.
- Platform never retries on its own. The caller (console or root) retries.

## Administrative state

- **Authoritative source (Proposal):** the presence of
  `/var/lib/sl-remote-management/enabled`, an empty file (root:root, 0644,
  type `sl_rm_state_t`). If it is absent, remote management is disabled, which
  is the default.
- **Persistence:** `/var` persists across reboots and across bootc deployment
  changes (update, rollback). Unlike `/etc`, it is not 3-way merged and not
  part of the image.
  - A rollback to an image without remote management (0.0.2) ignores the
    marker, and a later image honors it again.
  - **Interpretation (review):** a deployment change does not alter the
    administrative state.
- **Commit point:**
  - Enable: write a temporary file (`O_CREAT|O_EXCL`), `fsync` it, `rename`
    it to `enabled`, then `fsync` the directory.
  - Disable: `unlink`, then `fsync` the directory.
  - A crash leaves the marker either present or absent. A stale temporary
    file is removed by the next worker run.
- **Recovery after a failed worker:** the on-disk marker is the truth, and a
  retry of the same method converges.
- **`enabled` is not "service active":**
  - sl-managementd is statically enabled in the image, with
    `ConditionPathExists=` on the marker and on `tls/current`, so it starts at
    boot only when enabled and an identity exists.
  - The condition is evaluated only at start; Disable therefore also stops the
    service explicitly.
  - `listening` is a separate runtime fact (see "Status schema 0.4").
- **Considered, not chosen:** `systemctl enable` of sl-managementd.
  Enablement symlinks live in `/etc`, which is merged across deployments and
  editable by local administration, and it conflates the administrative
  decision with unit management.

## Concurrency

- **Proposal:** a new one-permit semaphore, `remote_management`, taken with
  `try_acquire` (`Busy` if held) by all four methods and held for the whole
  sequence, including worker waits. It is not shared with `mutation_starts`.
- **Rationale:**
  - These methods change no deployment or boot state, and
    update/rollback/reboot touch no remote-management state (`/var/lib/sl-remote-management`,
    sl-authd, sl-managementd).
  - Sharing the permit would make console actions `Busy` for the whole start
    evaluation of an update, and the reverse, for no safety gain.
- **Interaction:**
  - A reboot (`StartReboot`, or anything else) during a remote-management
    sequence is equivalent to a crash at the current step; the matrices define
    the result.
  - An update or rollback staged during a sequence does not affect it.
  - `StartReboot` does not wait for, or conflict with, remote-management
    workers (see Open questions).
- **Status reads:** `GetStatus` keeps its own `requests` permit and is not
  blocked by these methods.

## Authorization

**`org.signallayer.Platform1.conf` changes:**
- **Default context:** add explicit `<deny>` rules for all four new members,
  including `GetRemoteManagementEnrollment`, which returns the pairing code.
  `GetStatus` stays allowed as today.
- **`<policy user="root">`:** add four exact allows (destination, path,
  interface, member).
- **New `<policy user="sl-console">`:** exactly the same four allows and
  nothing else. There is no update, rollback or reboot, per the contract.
- **sl-managementd** gets no Platform1 allow at all. It reads status only
  through Session1.

**SELinux:**
- `sl_console_t` and `sl_platformd_t` exchange `send_msg`, added with the
  console in 5C-b.
- sl_platformd_t gains `start` and `status` on a new
  `sl_rm_worker_unit_file_t`, and `start stop status` on a new
  `sl_managementd_unit_file_t`.

**Limits, as already recorded in the contract:**
- UID-based policy admits any root process.
- The enrolled-console password requirement is enforced by the console UI and
  sl-authd, not by Platform.

## TLS identity

### Storage (Proposal)
| Path | Owner, mode | SELinux type | Readers |
|---|---|---|---|
| `/var/lib/sl-remote-management/` | root:root 0755 | `sl_rm_state_t` | — |
| `…/tls/` | root:sl-managementd 0750 | `sl_rm_tls_t` | sl-managementd, sl-platformd |
| `…/tls/current` | symlink to `gen-<16 hex>` | `sl_rm_tls_t` | sl-managementd, sl-platformd |
| `…/tls/gen-<16 hex>/` | root:sl-managementd 0750 | `sl_rm_tls_t` | sl-managementd, sl-platformd |
| `…/gen-*/key.pem` | root:sl-managementd 0640 | `sl_rm_tls_key_t` | sl-managementd only |
| `…/gen-*/cert.pem` | root:sl-managementd 0644 | `sl_rm_tls_t` | sl-managementd, sl-platformd |
| `…/gen-*/fingerprint` | root:root 0644 | `sl_rm_tls_t` | sl-platformd |

- **Writers:** only the worker domain writes any of these.
- **sl-console:** never readable. It is not in the sl-managementd group, and
  sl_console_t gets no rule for these types.
- **The private key:** SELinux allows only sl_managementd_t (read) and the
  worker domain (create and unlink). sl_platformd_t never reads it.
- **Rotation:**
  1. Write a new `gen-*` directory completely and `fsync` it.
  2. Atomically replace `current` (a symlink created under a temporary name,
     then `rename`d over `current`), and `fsync` `tls/`.
  3. Remove the old generation.
- **Readers** resolve `current` once and read the key, certificate and
  fingerprint from the same generation, so they never see a key from one
  identity with a certificate from another.

### Key type (Proposal)
ECDSA P-256 (prime256v1). Every current browser accepts it for TLS server
certificates, and it is fast to generate.
- **Alternative:** RSA-3072.
- **Not suitable:** Ed25519, because browsers do not support it for TLS server
  certificates.

### Generation (Proposal)
The worker runs, by `execve` with no shell, where `<gen>` is a directory path
the worker creates itself:

```text
/usr/bin/openssl req -x509 -new -newkey ec
  -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
  -noenc -keyout <gen>/key.pem -out <gen>/cert.pem
  -subj "/CN=SignalLayer CoreOS remote management"
  -not_after 99991231235959Z
  -addext basicConstraints=critical,CA:FALSE
  -addext keyUsage=critical,digitalSignature
  -addext extendedKeyUsage=serverAuth
```

```text
/usr/bin/openssl x509 -in <gen>/cert.pem -noout -fingerprint -sha256
```

- The subject is a single argv element; no quoting is involved because no
  shell is involved.
- The worker parses the second command's single output line strictly. It
  writes `fingerprint` only if the line has exactly the expected form.
- OpenSSL 3.5.8 is present in the pinned base, and therefore in the image.
  The workspace has no TLS, X.509 or SHA-2 crate, and none is added.
- **To verify in 5C-b step 2:** that `-not_after` is accepted by `openssl req`
  in 3.5.8, and that `openssl req -x509` sets a random serial number.

### Fingerprint (Proposal)
- **Algorithm:** SHA-256 over the DER encoding of the leaf certificate.
- **Canonical text:** the 32 bytes as uppercase hexadecimal pairs separated
  by `:`, 95 characters, for example `AB:CD:…:EF`. This is the form browser
  certificate viewers show.
- **Where it comes from:** the worker computes it once at generation and
  stores it in the generation directory. Platform reads and validates it and
  needs no hashing code of its own.

### Certificate contents (Proposal)
- Self-signed. The issuer and subject are both
  `CN=SignalLayer CoreOS remote management`.
- A random serial number, and validity from generation to 9999-12-31
  (RFC 5280's "no well-defined expiration").
- `basicConstraints CA:FALSE`, `keyUsage digitalSignature`,
  `extendedKeyUsage serverAuth`.
- **No subjectAltName**: no IP address, hostname or machine ID.
  - The contract's trust model is explicit fingerprint verification of a
    long-lived identity, not name validation.
  - Addresses on the primary interface are dynamic (DHCP, SLAAC, interface
    changes). Putting them in the certificate would require reissuing it
    whenever they change, which changes the fingerprint and breaks the owner's
    established trust.
  - Hostnames can change too, and would disclose local naming on the network.
  - **Consequence:** browsers always show the certificate as untrusted and
    name-mismatched. The owner proceeds after comparing the fingerprint with
    the console. How each browser presents that is a 5E observation.
- **Rotation:** only on Reenroll and the boot-time reset (removal). There is
  no scheduled rotation, per the contract.

## Network endpoint

- **Port (Proposal): 8443.** sl-managementd is unprivileged with no
  capabilities, so it cannot bind a port below 1024. Alternatives that were
  considered and rejected:
  - `CAP_NET_BIND_SERVICE` would be a new capability;
  - lowering `net.ipv4.ip_unprivileged_port_start` is a system-wide change;
  - systemd socket activation on 443 cannot follow the contract's
    dynamic-address binding, and would bind statically configured or all
    addresses.
- **URL format:**
  - IPv4: `https://192.0.2.10:8443/`
  - IPv6: `https://[2001:db8::10]:8443/`, bracketed, in RFC 5952 canonical
    form (Rust's `Ipv6Addr` display form, which the network observer's
    validated addresses already use).
  - Always with the trailing `/`.
- **Address selection (Proposal), from the primary connection's addresses:**
  - Exclude loopback, unspecified, multicast, IPv4 link-local
    (169.254.0.0/16) and IPv6 link-local (fe80::/10). Link-local IPv6 would
    need a zone identifier, which browsers do not accept in URLs.
  - Prefer IPv4; within a family, take the first address in the observer's
    strictly sorted order.
  - If no address qualifies, the URL is empty.

## Enrollment composition

`GetRemoteManagementEnrollment` composes its result from three owners, and
owns none of them:

| Field | Source |
|---|---|
| `url` | The network observer's validated primary connection (as used by `GetStatus`), plus the fixed port. |
| `fingerprint` | `tls/current/fingerprint`, written by the worker. |
| `pairing_code`, `expires_at` | `Auth1.GetPendingPairing`. |

## Boot-time reset

### Trigger evidence (Step 0)
- **Bootloader:** GRUB 2.12 (`grub2-efi-x64-2.12-64.fc44`), UEFI, installed
  from bootupd's static configuration (`bootupd-0.2.35-1.fc44`). The pinned
  base's `/usr/lib/bootupd/grub2-static/grub-static-pre.cfg` sets
  `timeout_style=menu` and `timeout=1`.
- **Serial console of every archived acceptance run** (4B, 4C, 4D, 4E, the
  0.0.2 release candidate; seven logs, all from disks built on the 0.0.2 base):
  - GRUB 2.12's menu is shown with "Press enter to boot the selected OS, `e'
    to edit the commands before booting or `c' for a command-line";
  - the countdown is 1 second;
  - the entries are only `Fedora Linux 44 (Forty Four) (ostree:N)` (one per
    deployment) and `UEFI Firmware Settings`.
- **No GRUB password:** `configs.d/01_users.cfg` sets `superusers` only if
  `${prefix}/user.cfg` exists (created by `grub2-set-password`), and nothing
  in this repository's image or disk build creates it. The installed disks'
  `/boot` was not inspected for it, so this is an inference, not proven.
- **Base versions:** the static configuration above was read from the current
  pinned base (Fedora 44, `sha256:ef8a660e…`). The serial evidence comes from
  0.0.2-base disks and shows the same 1-second menu.
- **Existing hooks that need a writer:** `configs.d/41_custom.cfg` sources
  `${prefix}/custom.cfg` if present. `configs.d/14_menu_show_once.cfg` honors
  `menu_show_once_timeout` from grubenv. Neither is written today.
- **Kernel command line:** the booted command line is
  `root=UUID=… rw console=tty0 console=ttyS0 console=ttyS0,115200n8 ostree=…`.

**What exists today:** editing the selected entry (`e`) or using the GRUB
command line (`c`) during the menu window. Edits apply to that boot only and
are never saved. No reset menu entry exists, and none can be added from the
image alone: `/boot` is not image content, and bootc manages the BLS
entries.

**Trust-boundary note:** the same edit path already allows `init=` and
`rd.break`, which give a root shell. A reset argument therefore does not widen
what a party at the boot console can do. The contract already assigns boot
protection (for example a GRUB password) to the operator.

### Proposed trigger (Proposal)
At the GRUB menu, the operator presses a key within the 1-second window, then
`e`, appends `signallayer.remote-management-reset` to the `linux` line, and
boots with Ctrl-X or F10. It applies to one boot only.

**Alternatives:**
| Alternative | Assessment |
|---|---|
| A dedicated menu entry through `${prefix}/custom.cfg` | Needs a writer to `/boot`, which does not exist. It would also be a permanent entry, which risks being selected by accident. |
| A persistent kernel argument (`/usr/lib/bootc/kargs.d`, `bootc` kargs) | Rejected: it is not one-boot, and would reset at every boot. |
| `systemd.unit=` to a reset target | The same edit mechanism, but it changes the whole boot target. |
| A longer menu window (image-provided `custom.cfg` or grubenv `menu_show_once_timeout`) | Also needs a writer, and would be a separate change. See Open questions. |

### Worker and ordering (Proposal)
`sl-rm-boot-reset.service`:
- `Type=oneshot`, with
  `ConditionKernelCommandLine=signallayer.remote-management-reset`.
- `Requires=` and `After=sl-authd.service`.
- `Before=sl-managementd.service sl-console.service sl-sessiond.service sl-platformd.service`.
- `WantedBy=multi-user.target`.
- `ExecStart=/usr/libexec/signallayer/sl-remote-worker boot-reset`.

The worker:
1. Calls `Auth1.ResetEnrollment` (as root, which the frozen matrix allows).
   This clears the credential, recovery key, any pairing and all backoff.
2. Durably removes `tls/current` and every generation.

It does not touch the enabled marker, the OS or anything else.

**Fail closed (Proposal):** `sl-managementd.service` has `Requires=` and
`After=` on the reset unit.
- When the kernel argument is absent, the condition skips the unit, which
  does not fail its dependents.
- When the reset fails, sl-managementd does not start.
- sl-console is only ordered after the reset, so the owner can still see the
  failure. How the console presents it is an Open question.

### State after a successful reset
| Fact | Value | Why |
|---|---|---|
| enabled | **unchanged** | The contract lists what the reset wipes: the operator credential, the recovery key and the TLS identity. The administrative decision is not among them. |
| listening | false | No TLS identity exists, so sl-managementd's `ConditionPathExists=…/tls/current` fails. There is no usable state to listen with. |
| enrolled | false | `ResetEnrollment`. |
| TLS identity | absent | Removed. The next Enable generates a new one; the fingerprint necessarily changes. |
| pending pairing | none | The reset creates no pairing. A new pairing requires the owner's explicit local Enable, which also generates the identity and starts sl-managementd. |

## Status schema 0.4

- Platform's `GetStatus` is unchanged and stays schema 0.3, so corectl is
  unaffected.
- Session1's `GetPlatformStatus` returns schema 0.4: Platform's 0.3 status
  plus `remote_management`, which Session1 aggregates without owning. That is
  the only change in Session1.
- **Interpretation (review):** the contract says the existing Platform
  methods are unchanged and that Session1 aggregates, so the 0.4 schema is
  produced by Session1, not by Platform.

| Field | Owner | How Session1 reads it |
|---|---|---|
| `enabled` | Platform's administrative state | Presence of the enabled marker. sl_sessiond_t gets `getattr` on `sl_rm_state_t`, and no other access. **Interpretation (review):** the alternative is a fifth Platform method, which the contract's list of four does not include. |
| `listening` | sl-managementd | **Proposal:** sl-managementd creates `/run/sl-managementd/listening` only while it accepts eligible connections, and removes it when it stops accepting. The directory is the unit's `RuntimeDirectory=`, which systemd removes when the service stops for any reason, including a crash. Absent means false. |
| `enrolled` | sl-authd | `Auth1.GetEnrollmentState().enrolled`. sl-sessiond is already in the frozen caller matrix for this method. |

- **Before sl-managementd exists** (and on an image without it), `listening`
  is false because its runtime file cannot exist.
- `enabled` is false until an Enable, and `enrolled` comes from sl-authd as
  usual.
- **Failures (Proposal):** if sl-authd cannot be read, Session1 returns a
  distinct error, never a guessed `false`. The status carries no pairing
  code, key material, counters or session counts, per the contract.

## Properties provable by unit tests

These assume injected systemd, sl-authd and filesystem backends, and a
temporary directory.
- **Signatures:** each new method is zero-argument, and an argument is
  rejected with `InvalidArgs` before any permit is taken.
- **Sequences:** the exact steps of Enable, Disable and Reenroll, and that each
  failure point in the matrices produces the listed error and stops there.
  Reenroll never starts sl-managementd after a failed reset, rotation or
  pairing.
- **Idempotency:** repeated calls on a converged state perform only no-ops.
- **Permit:** a second remote-management call is `Busy`, and remote management
  and `mutation_starts` do not block each other.
- **Enrollment composition:**
  - IPv4 and bracketed IPv6 URLs;
  - address selection and exclusions;
  - an empty URL with no eligible address;
  - an empty fingerprint with no identity;
  - a malformed fingerprint file is an error;
  - empty/zero pairing fields when none is pending;
  - no credential-creating call is ever made.
- **Worker (`sl-remote-worker`):**
  - the fixed argv lists;
  - strict parsing of the fingerprint line;
  - atomic marker create and remove;
  - generation-directory swap with simulated failures leaving the previous
    state;
  - removal of a stale temporary file;
  - boot-reset step order.
- **Status 0.4 composition:** field sources, absence handling, and an error
  (not `false`) when sl-authd fails.
- **Static assertions (image build):** the Platform1 bus policy for root and
  sl-console, the unit files, file contexts and ownership. Static only.

## Deferred to 5E (runtime; not claimed here)
- **Bus policy:** the installed policy admits exactly root and sl-console to
  the four methods under the real bus, and sl-managementd to none.
- **systemd:** worker, stop, start and condition behavior under the real
  manager, including `Requires=` fail-closed on a failed boot reset.
- **SELinux:** confinement of the worker, sl-managementd and sl-console
  domains, and the key readable only by sl-managementd.
- **TLS on the real system:**
  - `openssl` generation with the fixed argv in the real image, including
    `-not_after`;
  - the certificate contents and random serial;
  - the fingerprint matches what browsers display;
  - browser acceptance behavior.
- **Persistence:** the enabled marker and identity survive reboot and a
  deployment change.
- **Boot reset:**
  - the GRUB edit path on the real console (serial and VGA);
  - the reset runs once and before sl-managementd, sl-console, sl-sessiond and
    sl-platformd;
  - the resulting state table above.
- **`listening` accuracy:** the runtime file matches actual acceptance of
  connections.
- **Consistency:** status agrees between corectl (0.3) and Session1 (0.4).

## Interpretations flagged for review
1. Web sessions exist only in sl-managementd's memory, so stopping it
   invalidates them.
2. Reenroll does not change `enabled`, and on a disabled machine creates a
   pairing without starting sl-managementd.
3. The optional pairing fields are expressed as `""` and `0` in a fixed
   `(ssst)` return.
4. A bootc deployment change does not alter the administrative state.
5. Schema 0.4 is produced by Session1; Platform's `GetStatus` stays 0.3.
6. Session1 reads `enabled` from the marker file, rather than through a fifth
   Platform method.

## Open questions
1. **Menu window:** is a 1-second GRUB menu window acceptable for the reset
   trigger (the operator must press a key within it, which hypervisor consoles
   can miss)? Or should the image lengthen it? Doing so needs a writer to
   `/boot` or grubenv, which is new.
2. **Kernel argument name:** `signallayer.remote-management-reset`.
3. **Console after a failed reset:** how sl-console should present a requested
   but failed boot reset, given sl-managementd is held back.
4. **Reboot during a sequence:** should `StartReboot` be refused
   (`Conflict`) while a remote-management worker or sequence is running, or is
   crash-equivalence enough?
5. **sl-authd unavailable in status:** should Session1 fail the whole status,
   as proposed, or report status without `remote_management`? The latter would
   change the schema's shape.
6. **Several eligible addresses:** should `url` expose only one (as proposed),
   or should the contract's single `url` field stay while the console also
   lists alternatives?
7. **Timeouts:** 30 seconds for workers and 10 seconds for starting or
   stopping sl-managementd.
