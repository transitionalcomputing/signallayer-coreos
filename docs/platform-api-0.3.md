# Platform API 0.3: remote-management lifecycle (0.0.3)

**Status:** 5C-b frozen. Derived from the frozen
[0.0.3 remote management contract](remote-management-0.0.3.md), including its
5C-b amendment, and the frozen [sl-authd interface](authd-interface-0.0.3.md).

- Three items are deliberately left to 5C-b step 2 and are marked **Step 2
  check**: the openssl path, `-not_after` support and the random serial
  number. If a check fails, step 2 stops and reports it before implementing
  the affected item.
- Places where the contract had to be interpreted are marked **Accepted
  interpretation**, and are listed again at the end.
- No review items remain.

## Safety property: destructive reset

Once a destructive reset begins, remote management cannot return to normal
service until the reset completes successfully or is explicitly superseded by
Reenroll. The `reset-pending` marker (see "Administrative state") carries this
across failures, crashes and reboots.

## Phase boundaries

- **5C-b implements the Platform side:**
  - the four Platform1 methods and `run_worker`;
  - the `sl-remote-worker` binary and its five worker units;
  - the Platform1 bus-policy changes;
  - the SELinux rules for sl_platformd_t, the worker domain and the
    remote-management file types;
  - Session1's schema 0.4 aggregation.
- **5C-b designs against, but does not build:**
  - sl-remoted, built in 5C-c;
  - sl-console, built in 5C-d.

  Their units, their SELinux domains (`sl_remoted_t`, `sl_console_t`), the
  `sl_remoted_unit_file_t` type and every rule that names them are added in
  those phases, not in 5C-b.
- **Consequence for 5C-b:** the Platform sequences that start or stop
  sl-remoted are verified with an injected systemd backend. At runtime,
  Enable cannot complete its last step until sl-remoted exists (5C-c).

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
  - Reenroll rotates the TLS identity, and creates a fresh pairing only on an
    enabled machine (contract amendment).

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

## Components

| Unit or file | Built in | Purpose |
|---|---|---|
| `sl-rm-enable.service` | 5C-b | Oneshot worker: ensure a TLS identity exists (generate only if absent), then durably create the enabled marker. |
| `sl-rm-disable.service` | 5C-b | Oneshot worker: durably remove the enabled marker. |
| `sl-rm-rotate.service` | 5C-b | Oneshot worker: generate a new TLS identity and atomically replace the current one. |
| `sl-rm-boot-reset.service` | 5C-b | Oneshot early-boot worker: the boot-time reset. |
| `sl-rm-clear-reset.service` | 5C-b | Oneshot worker: durably remove the `reset-pending` marker, as the final durable step of Reenroll. |
| `/usr/libexec/signallayer/sl-remote-worker` | 5C-b | One Rust binary for the five worker units. Each unit's `ExecStart=` is a fixed argv selecting one fixed mode (`enable`, `disable`, `rotate-tls`, `boot-reset`, `clear-reset-pending`). It takes no other input, runs no shell, and runs openssl only with the fixed argv lists below. |
| `sl-remoted.service` | 5C-c | The HTTPS server. Unprivileged, no capabilities. Static `WantedBy=multi-user.target`, with `ConditionPathExists=` on the enabled marker and on `tls/current`, and `ConditionPathExists=!/var/lib/sl-remote-management/reset-pending`. It never starts while a reset is pending. |
| sl-console | 5C-d | The local console UI. |

Every worker run that writes under `tls/` also removes any generation
directory that `current` does not reference.

Platform needs one new helper beside `start_worker`: `run_worker`.
- It starts a oneshot worker the same way, then waits, within a bounded
  timeout, for that invocation to finish.
- It succeeds only if the unit returns to `inactive` with
  `Result=success`.
- Any other outcome is `RemoteManagementUnavailable`.
- **Timeouts:** 30 seconds for a worker, and 10 seconds for starting or
  stopping sl-remoted.

## Methods

All four are zero-argument. `CheckedPlatform`'s `ZERO_ARGUMENT_METHODS` gains
them, so an argument is rejected with `InvalidArgs` before any permit is taken
or state is read.

### New errors
| Error | Meaning |
|---|---|
| `RemoteManagementUnavailable` | A fixed worker, sl-remoted, or remote-management state could not be controlled or read. |
| `AuthUnavailable` | An sl-authd call failed. The sl-authd error name is not passed through, and the message is fixed. |
| `ResetIncomplete` | A destructive boot reset began and did not complete (`reset-pending` exists). Returned by Enable before any side effect. Reenroll repairs it. |

`Busy` and `NetworkUnavailable` are reused with their existing meaning.

### EnableRemoteManagement() -> ()
**Steps:**
1. Take the remote-management permit, or return `Busy`.
2. If `reset-pending` exists, return `ResetIncomplete`. Nothing else happens:
   no TLS identity is generated, the enabled marker is not touched, sl-authd
   is not called and sl-remoted is not started. If the marker cannot be
   checked, return `RemoteManagementUnavailable`, also with no side effect.
3. `run_worker(sl-rm-enable.service)`:
   1. as defense in depth, the worker fails without any change if
      `reset-pending` exists;
   2. if no TLS identity exists, generate one; an existing identity is never
      rotated;
   3. durably create the enabled marker. **This is the commit point for
      `enabled`.**
4. Call `Auth1.EnsurePendingPairing`. This creates a pairing only when no
   operator is enrolled and no unexpired pairing exists, and never rotates a
   code.
5. `StartUnit(sl-remoted.service, "fail")` if it is not active, and wait
   until it is active.

**Errors:** `Busy`, `ResetIncomplete`, `RemoteManagementUnavailable`,
`AuthUnavailable`.

**Idempotency:** on a fully enabled machine every step is a no-op. If the
previous pairing expired and no operator is enrolled, step 4 creates a new one,
as the contract requires. The TLS identity is never rotated.

### DisableRemoteManagement() -> ()
**Steps:**
1. Take the permit, or return `Busy`.
2. `run_worker(sl-rm-disable.service)`: durably remove the enabled marker.
   **This is the commit point for `enabled`.** From here on, sl-remoted
   cannot be started at boot, because its condition fails.
3. `StopUnit(sl-remoted.service, "replace")`, and wait until it is
   inactive. All web sessions end with the process.
4. Call `Auth1.CancelPendingPairing`.

Enrollment and the TLS identity are preserved.

**Errors:** `Busy`, `RemoteManagementUnavailable`, `AuthUnavailable`.

**Idempotency:** on a disabled machine every step is a no-op.

Disable is allowed while `reset-pending` exists: it only removes the enabled
marker, stops sl-remoted and cancels a pairing, and does not touch the reset
marker.

**Accepted interpretation:** web sessions are held only in sl-remoted's
memory, so stopping it invalidates them all.

### ReenrollRemoteManagement() -> ()
**Steps:**
1. Take the permit, or return `Busy`.
2. `StopUnit(sl-remoted.service)`, and wait until it is inactive. This
   ends all sessions and closes the login and pairing path before the
   credential changes.
3. Call `Auth1.ResetEnrollment`. **This is the commit point for invalidating
   the old credential.** It also clears any pairing and all sl-authd backoff
   counters.
4. `run_worker(sl-rm-rotate.service)`: a new identity is atomically swapped
   in. **This is the commit point for the TLS rotation.**
5. If the enabled marker exists (Platform reads it under the permit), call
   `Auth1.EnsurePendingPairing`, which creates a fresh pairing. On a disabled
   machine no pairing is created (contract amendment).
6. If `reset-pending` exists, `run_worker(sl-rm-clear-reset.service)`:
   durably remove it (`unlink`, then `fsync` the directory). **This is the
   final durable step.** It runs only after the sequence has converged: the
   authentication reset succeeded, the new TLS identity is durably
   installed, and the pairing behavior matches the enabled or disabled state.
7. If the enabled marker exists, `StartUnit(sl-remoted.service)`. This is a
   runtime step, not a durable one.

**On an administratively disabled machine** (contract amendment), Reenroll
skips steps 5 and 7: enrollment is reset and the TLS identity rotated, no
pairing is created, and any `reset-pending` marker is cleared. The next
explicit Enable creates the pairing and starts sl-remoted.

**Reenroll is the explicit repair path** for an incomplete boot reset: it
performs every destructive step of the reset itself (authentication reset, TLS
replacement), and only then clears the marker.

**Order of the marker clear and the sl-remoted start (decided):**
1. All durable security state converges: the authentication reset, the new
   TLS identity, and the pairing behavior for the enabled or disabled state.
2. `reset-pending` is durably cleared.
3. sl-remoted is started.

The start is runtime convergence, not part of the reset-pending safety commit.
sl-remoted's `!reset-pending` condition would prevent it from starting any
earlier. A failed start is an ordinary enabled-but-not-listening failure
(row 7 below): a new identity, no old credential, and a retry through Enable or
Reenroll.

**Permit:** the remote-management permit is held from Reenroll step 1 through
the marker clear (Reenroll step 6) and the sl-remoted start attempt (Reenroll
step 7), and released
only when Reenroll returns. No other remote-management method can observe or
act on the state between the clear and the start.

**Errors:** `Busy`, `RemoteManagementUnavailable`, `AuthUnavailable`. Reenroll
never returns `ResetIncomplete`.

**Order rationale:** the credential is reset before the TLS identity is rotated.
A failure between the two therefore leaves the old credential invalid, not the
old credential valid behind a new fingerprint. sl-remoted is started only
after every earlier step succeeded, so it never serves an unenrolled machine
with a stale identity as the result of this call.

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
and it never reads the private key. It does not report `reset-pending`.

**Formatting:** the console displays the code as `XXXX-XXXX`; Platform returns
it unformatted, as sl-authd does.

**Accepted interpretation:** the contract's `pairing_code` and `expires_at`,
"present only while a pairing is pending", are expressed with a fixed `(ssst)`
signature and empty/zero values, not optional types.

## Postcondition and failure matrices

Columns give the state after the failure. "Unchanged" means as before the call.

### Enable
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | Retry |
|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | Retry Enable. |
| 2 `reset-pending` exists (`ResetIncomplete`) | unchanged | unchanged | unchanged | unchanged | unchanged | Enable cannot succeed; Reenroll repairs. |
| 3.2 identity generation | unchanged | unchanged | unchanged | unchanged (nothing is swapped in on failure) | unchanged | Retry Enable. |
| 3.3 marker write | unchanged | unchanged | unchanged | present (possibly just generated; never rotated later by Enable) | unchanged | Retry Enable; 3.2 is then a no-op. |
| 4 sl-authd | **true** | unchanged | unchanged | present | unchanged | Retry Enable; 3 is a no-op. |
| 5 start sl-remoted | true | false | unchanged | present | pending if unenrolled | Retry Enable: the pairing is not rotated while unexpired. At the next boot the service also starts, because the marker and identity exist. |

### Disable
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | Retry |
|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | Retry. |
| 2 marker removal | unchanged | unchanged | unchanged | unchanged | unchanged | Retry Disable. |
| 3 stop sl-remoted | **false** | possibly true | unchanged | unchanged | unchanged | Retry Disable. Status shows the inconsistency (`enabled` false, `listening` true) rather than hiding it. A reboot also ends it, because the service's condition now fails. |
| 4 cancel pairing | false | false | unchanged | unchanged | may remain pending until it expires (at most 10 minutes); unreachable because nothing listens | Retry Disable. |

### Reenroll
The `reset-pending` column applies when Reenroll repairs an incomplete boot
reset. Without one, the marker does not exist and stays absent.

| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | reset-pending | Retry |
|---|---|---|---|---|---|---|---|
| Permit busy | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | Retry. |
| 2 stop sl-remoted | unchanged | unknown; status shows it | unchanged | unchanged | unchanged | unchanged | Retry Reenroll. |
| 3 sl-authd reset | unchanged | false | unchanged | unchanged | unchanged | unchanged | Retry Reenroll. Without a pending reset, until the retry or at the next boot the machine is as before the call. With one, sl-remoted stays blocked. |
| 4 rotation | unchanged | false | **false** | old identity, or none after a partial boot reset (no partial identity) | none | unchanged | Retry Reenroll (the reset repeats harmlessly). Without a pending reset, a reboot before the retry starts sl-remoted (if enabled) with the old identity, unenrolled and with no pairing: nobody can pair until a local Enable or Reenroll. With one, sl-remoted stays blocked and Enable returns `ResetIncomplete`. |
| 5 pairing (enabled only) | true | false | false | **new** | none | unchanged | Retry Reenroll (rotates again; nothing is enrolled). Enable also completes it when no reset is pending; while one is pending, only Reenroll does. |
| 6 clear `reset-pending` | unchanged | false | false | new | pending if enabled | **still present** | Retry Reenroll. sl-remoted stays blocked and Enable returns `ResetIncomplete` until it succeeds. |
| 7 start sl-remoted (enabled only) | true | false | false | new | pending | **absent** | An ordinary enabled-but-not-listening failure, outside the reset-pending safety commit. Retry Enable, or Reenroll. |
| None, on a disabled machine (success) | false | false | false | new | **none** | absent | Not a failure: the next explicit Enable creates the pairing and starts sl-remoted. |

**General rules:**
- Every step is individually durable or memory-only, and idempotent. A crash
  or reboot at any point is equivalent to a failure at that step.
- No failure leaves a partially written marker or TLS identity.
- Platform never retries on its own. The caller (console or root) retries.

## Administrative state

- **Authoritative source:** the presence of
  `/var/lib/sl-remote-management/enabled`, an empty file (root:root, 0644,
  type `sl_rm_state_t`). If it is absent, remote management is disabled, which
  is the default.
- **Persistence:** `/var` persists across reboots and across bootc deployment
  changes (update, rollback). Unlike `/etc`, it is not 3-way merged and not
  part of the image.
  - A rollback to an image without remote management (0.0.2) ignores the
    marker, and a later image honors it again.
  - **Accepted interpretation:** a deployment change does not alter the
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
  - sl-remoted is statically enabled in the image, with
    `ConditionPathExists=` on the marker and on `tls/current`, so it starts at
    boot only when enabled and an identity exists.
  - The condition is evaluated only at start; Disable therefore also stops the
    service explicitly.
  - `listening` is a separate runtime fact (see "Status schema 0.4").
- **Reset-pending marker:** `/var/lib/sl-remote-management/reset-pending`,
  an empty file with the same ownership, mode and SELinux type as the enabled
  marker (root:root, 0644, `sl_rm_state_t`).
  - It is created only by the boot-reset worker, as the boot reset's first
    durable commit point (temporary file, `fsync`, `rename`, `fsync` the
    directory).
  - It is removed only by the boot-reset worker after every reset step
    succeeded, or by Reenroll's final durable step.
  - It survives crashes and reboots like the enabled marker.
  - **Two enforcement layers**, both required:
    - **The Enable path:** `EnableRemoteManagement`'s `ResetIncomplete`
      pre-check is authoritative. While the marker exists, Enable fails
      with no side effects.
    - **Boot-time and direct starts:** the sl-remoted unit's
      `ConditionPathExists=!/var/lib/sl-remote-management/reset-pending` is
      authoritative. Nothing calls Enable at boot, so only the condition
      stops sl-remoted there, and it also stops any direct `systemctl start`.
  - It is not exposed through Session1 or schema 0.4. sl-console learns of it
    only through the `ResetIncomplete` error, and renders it along the lines
    of "A previous remote-management reset did not complete. Re-enroll to
    repair it." The exact text is 5C-d's.
- **Considered, not chosen:** `systemctl enable` of sl-remoted.
  Enablement symlinks live in `/etc`, which is merged across deployments and
  editable by local administration, and it conflates the administrative
  decision with unit management.

## Concurrency

- **The permit:** a new one-permit semaphore, `remote_management`, taken with
  `try_acquire` (`Busy` if held) by all four methods and held for the whole
  sequence, including worker waits. It is not shared with `mutation_starts`.
- **Rationale:**
  - These methods change no deployment or boot state, and
    update/rollback/reboot touch no remote-management state (`/var/lib/sl-remote-management`,
    sl-authd, sl-remoted).
  - Sharing the permit would make console actions `Busy` for the whole start
    evaluation of an update, and the reverse, for no safety gain.
- **Interaction:**
  - A reboot (`StartReboot`, or anything else) during a remote-management
    sequence is equivalent to a crash at the current step; the matrices define
    the result.
  - This crash-equivalence is sufficient: `StartReboot` does not refuse,
    wait for or conflict with remote-management sequences.
  - An update or rollback staged during a sequence does not affect it.
- **Status reads:** `GetStatus` keeps its own `requests` permit and is not
  blocked by these methods.

## Authorization

**`org.signallayer.Platform1.conf` changes (5C-b):**
- **Default context:** add explicit `<deny>` rules for all four new members,
  including `GetRemoteManagementEnrollment`, which returns the pairing code.
  `GetStatus` stays allowed as today.
- **`<policy user="root">`:** add four exact allows (destination, path,
  interface, member).
- **New `<policy user="sl-console">`:** exactly the same four allows and
  nothing else. There is no update, rollback or reboot, per the contract. The
  sl-console account is already reserved by sysusers.
- **sl-remoted** gets no Platform1 allow at all. It reads status only
  through Session1.

**SELinux:**
- **5C-b:** sl_platformd_t gains `start` and `status` on a new
  `sl_rm_worker_unit_file_t`.
- **5C-c (with sl-remoted):** `start stop status` on a new
  `sl_remoted_unit_file_t`.
- **5C-d (with sl-console):** `sl_console_t` and `sl_platformd_t` exchange
  `send_msg`.

**Limits, as already recorded in the contract:**
- UID-based policy admits any root process.
- The enrolled-console password requirement is enforced by the console UI and
  sl-authd, not by Platform.

## TLS identity

### Storage
| Path | Owner, mode | SELinux type | Readers |
|---|---|---|---|
| `/var/lib/sl-remote-management/` | root:root 0755 | `sl_rm_state_t` | — |
| `…/enabled`, `…/reset-pending` | root:root 0644 | `sl_rm_state_t` | sl-platformd; sl-sessiond (`getattr` on `enabled` only) |
| `…/tls/` | root:sl-remoted 0750 | `sl_rm_tls_t` | sl-remoted, sl-platformd |
| `…/tls/current` | symlink to `gen-<16 hex>` | `sl_rm_tls_t` | sl-remoted, sl-platformd |
| `…/tls/gen-<16 hex>/` | root:sl-remoted 0750 | `sl_rm_tls_t` | sl-remoted, sl-platformd |
| `…/gen-*/key.pem` | root:sl-remoted 0640 | `sl_rm_tls_key_t` | sl-remoted only |
| `…/gen-*/cert.pem` | root:sl-remoted 0644 | `sl_rm_tls_t` | sl-remoted, sl-platformd |
| `…/gen-*/fingerprint` | root:root 0644 | `sl_rm_tls_t` | sl-platformd |

- **Writers:** only the worker domain writes any of these.
- **sl-console:** never readable. It is not in the sl-remoted group, and
  sl_console_t (5C-d) gets no rule for these types.
- **The private key:** SELinux allows only sl_remoted_t (read, 5C-c) and the
  worker domain (create and unlink). sl_platformd_t never reads it.
- **Rotation:**
  1. Write a new `gen-*` directory completely and `fsync` it.
  2. Atomically replace `current` (a symlink created under a temporary name,
     then `rename`d over `current`), and `fsync` `tls/`.
  3. Remove the old generation.
- **Readers** resolve `current` once and read the key, certificate and
  fingerprint from the same generation, so they never see a key from one
  identity with a certificate from another.

### Key type
ECDSA P-256 (prime256v1). Every current browser accepts it for TLS server
certificates, and it is fast to generate. Ed25519 is not used, because browsers
do not support it for TLS server certificates.

### Generation
The worker runs, by `execve` with no shell, where `<openssl>` is a fixed
absolute path and `<gen>` is a directory path the worker creates itself:

```text
<openssl> req -x509 -new -newkey ec
  -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve
  -noenc -keyout <gen>/key.pem -out <gen>/cert.pem
  -subj "/CN=SignalLayer CoreOS remote management"
  -not_after 99991231235959Z
  -addext basicConstraints=critical,CA:FALSE
  -addext keyUsage=critical,digitalSignature
  -addext extendedKeyUsage=serverAuth
```

```text
<openssl> x509 -in <gen>/cert.pem -noout -fingerprint -sha256
```

- The subject is a single argv element; no quoting is involved because no
  shell is involved.
- The worker parses the second command's single output line strictly. It
  writes `fingerprint` only if the line has exactly the expected form.
- OpenSSL 3.5.8 is present in the pinned base, and therefore in the image.
  The workspace has no TLS, X.509 or SHA-2 crate, and none is added.
- **Step 2 checks:**
  1. **Path:** resolve the openssl binary's actual absolute path in the
     pinned base, and fix that path in the worker. Step 0 found
     `/usr/sbin/openssl` via `command -v`; this document freezes no path.
  2. **`-not_after`:** confirm that `openssl req` in 3.5.8 accepts it.
  3. **Serial:** confirm that `openssl req -x509` sets a random serial
     number.

### Fingerprint
- **Algorithm:** SHA-256 over the DER encoding of the leaf certificate.
- **Canonical text:** the 32 bytes as uppercase hexadecimal pairs separated
  by `:`, 95 characters, for example `AB:CD:…:EF`. This is the form browser
  certificate viewers show.
- **Where it comes from:** the worker computes it once at generation and
  stores it in the generation directory. Platform reads and validates it and
  needs no hashing code of its own.

### Certificate contents
- Self-signed. The issuer and subject are both
  `CN=SignalLayer CoreOS remote management`.
- A random serial number (Step 2 check), and validity from generation to
  9999-12-31 (RFC 5280's "no well-defined expiration"; `-not_after` is a
  Step 2 check).
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

- **Port: 8443.** sl-remoted is unprivileged with no capabilities, so it
  cannot bind a port below 1024. Alternatives that were considered and
  rejected:
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
- **Address selection:** exactly one `url`, chosen from the primary
  connection's addresses:
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

### Pre-OS boundary
Pre-OS console access is equivalent to machine-owner access in 0.0.3. Normal
enrolled SignalLayer console operations require the operator password, but
bootloader, firmware, hypervisor-console or equivalent pre-OS access is outside
that authentication boundary.

The contract records the same boundary in its Trust model, and lists locking
it down under its deferred hardening items.

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

**What exists today:** per the menu's own hint, editing the selected entry or
using the GRUB command line during the menu window. Edits apply to that boot
only and are never saved. No reset menu entry exists, and none can be added
from the image alone: `/boot` is not image content, and bootc manages the BLS
entries.

**Trust-boundary note:** the same edit path already allows `init=` and
`rd.break`, which give a root shell. A reset argument therefore does not widen
what a party at the boot console can do (see "Pre-OS boundary").

### Trigger (0.0.3)
- The kernel argument is `signallayer.remote-management-reset`, added by a
  one-boot GRUB edit.
- During startup, the operator interrupts the GRUB menu within its 1-second
  window, edits the selected entry, appends the argument to the kernel command
  line, and boots the edited entry.
- Which keys interrupt the countdown, open the editor and boot the edited
  entry on this GRUB configuration is verified in 5E. This document does not
  name them as fact.
- The 1-second window is accepted for 0.0.3. Replacing this trigger is a
  hardening item in the contract.

**Alternatives considered:**
| Alternative | Assessment |
|---|---|
| A dedicated menu entry through `${prefix}/custom.cfg` | Needs a writer to `/boot`, which does not exist. It would also be a permanent entry, which risks being selected by accident. |
| A persistent kernel argument (`/usr/lib/bootc/kargs.d`, `bootc` kargs) | Rejected: it is not one-boot, and would reset at every boot. |
| `systemd.unit=` to a reset target | The same edit mechanism, but it changes the whole boot target. |
| A longer menu window (image-provided `custom.cfg` or grubenv `menu_show_once_timeout`) | Also needs a writer. Not in 0.0.3. |

### Worker and ordering
`sl-rm-boot-reset.service`:
- `Type=oneshot`, with
  `ConditionKernelCommandLine=signallayer.remote-management-reset`.
- `Requires=` and `After=sl-authd.service`.
- `Before=sl-remoted.service sl-console.service sl-sessiond.service sl-platformd.service`.
  Ordering against units that do not exist yet (sl-remoted and sl-console,
  before 5C-c and 5C-d) is inert.
- `WantedBy=multi-user.target`.
- `ExecStart=/usr/libexec/signallayer/sl-remote-worker boot-reset`.

**Steps (fail closed across boots):**
0. **Durably create `reset-pending`:** temporary file, `fsync`, `rename`,
   then `fsync` the directory. If it already exists, from an earlier
   incomplete reset, this is a no-op. **This is the first durable commit
   point.** If creating it fails, the reset does not begin and no destructive
   action occurs.
1. **Durably remove `tls/current`:** `unlink` the symlink, then `fsync`
   `tls/`. From this commit on, sl-remoted's `ConditionPathExists=…/tls/current`
   fails on every later boot, until an explicit Enable or Reenroll creates a
   new identity.
2. **Call `Auth1.ResetEnrollment`** (as root, which the frozen matrix
   allows). This clears the credential, recovery key, any pairing and all
   backoff.
3. **Remove every old generation directory**, then `fsync` `tls/`.
4. **Durably remove `reset-pending`** (`unlink`, then `fsync` the directory),
   only after steps 1 to 3 all succeeded.

It does not touch the enabled marker, the OS or anything else.

**Within the same boot:** `sl-remoted.service` (5C-c) has `Requires=` and
`After=` on the reset unit.
- When the kernel argument is absent, the condition skips the unit, which
  does not fail its dependents.
- When the reset fails, sl-remoted does not start in that boot. On every
  later boot, its `!reset-pending` condition keeps it stopped.
- sl-console is only ordered after the reset, and must visibly report that a
  requested boot reset failed. The mechanism is defined in 5C-d.

### Boot-reset failure matrix
| Failure point | enabled | listening | enrolled | TLS identity | pending pairing | reset-pending | Later boots and repair |
|---|---|---|---|---|---|---|---|
| 0 create `reset-pending` | unchanged | false (sl-remoted is held back this boot) | unchanged | unchanged | none | absent | The reset did not begin, and nothing destructive happened. sl-console reports the failed reset. A later boot without the argument is the machine exactly as before the reset request. |
| 1 remove `tls/current` | unchanged | false | unchanged | unchanged, but unusable | none | **present** | sl-remoted cannot start on any later boot (`!reset-pending`), even though the old identity is still on disk. Enable returns `ResetIncomplete`. Reenroll repairs. |
| 2 `ResetEnrollment` | unchanged | false | **unchanged (old credential still valid)** | `current` removed | none | present | sl-remoted cannot start on any later boot. Enable returns `ResetIncomplete`, so no new identity can be paired with the old credential. Reenroll repairs. |
| 3 remove old generations | unchanged | false | false | `current` absent; unreferenced old files remain | none | present | sl-remoted cannot start. Enable returns `ResetIncomplete`. Reenroll repairs, and its rotation removes the leftovers. |
| 4 remove `reset-pending` | unchanged | false | false | absent | none | present | Every destructive step completed, but the marker remains. Enable returns `ResetIncomplete`. Reenroll repairs. |
| Worker crash or power loss | as for the step reached | | | | | | The same as a failure at that step. |

After a failure at step 1 or later, repeating the boot reset (booting again
with the argument) can also complete it, because every step is idempotent.
Reenroll is the repair path from the running system.

**The marker survives crashes and reboots.** A later boot without the one-shot
kernel argument skips the reset unit, but that reopens nothing: the marker
still blocks sl-remoted and Enable.

**Invariant:** once `reset-pending` has committed (step 0), remote management
cannot return to normal service until the reset completes, or is superseded by
Reenroll. In particular, sl-remoted never serves the old TLS identity, and
Enable never pairs a new identity with the old credential.

### State after a successful reset
| Fact | Value | Why |
|---|---|---|
| enabled | **unchanged** | The contract lists what the reset wipes: the operator credential, the recovery key and the TLS identity. The administrative decision is not among them. |
| listening | false | No TLS identity exists, so sl-remoted's `ConditionPathExists=…/tls/current` fails. There is no usable state to listen with. |
| enrolled | false | `ResetEnrollment`. |
| TLS identity | absent | Removed. The next Enable generates a new one; the fingerprint necessarily changes. |
| pending pairing | none | The reset creates no pairing. A new pairing requires the owner's explicit local Enable, which also generates the identity and starts sl-remoted. |

## Status schema 0.4

- Platform's `GetStatus` is unchanged and stays schema 0.3, so corectl is
  unaffected.
- Session1's `GetPlatformStatus` returns schema 0.4: Platform's 0.3 status
  plus `remote_management`, which Session1 aggregates without owning. That is
  the only change in Session1.
- **Accepted interpretation:** the contract says the existing Platform
  methods are unchanged and that Session1 aggregates, so the 0.4 schema is
  produced by Session1, not by Platform.

| Field | Owner | How Session1 reads it |
|---|---|---|
| `enabled` | Platform's administrative state | Presence of the enabled marker. sl_sessiond_t gets `getattr` on `sl_rm_state_t`, and no other access. **Accepted interpretation:** this is used instead of a fifth Platform method, which the contract's list of four does not include. |
| `listening` | sl-remoted (5C-c) | sl-remoted creates `/run/sl-remoted/listening` only while it accepts eligible connections, and removes it when it stops accepting. The directory is the unit's `RuntimeDirectory=`, which systemd removes when the service stops for any reason, including a crash. Absent means false. |
| `enrolled` | sl-authd | `Auth1.GetEnrollmentState().enrolled`. sl-sessiond is already in the frozen caller matrix for this method. |

- **Before sl-remoted exists** (before 5C-c, and on an image without it),
  `listening` is false because its runtime file cannot exist.
- `enabled` is false until an Enable, and `enrolled` comes from sl-authd as
  usual.
- **Failures:** if sl-authd cannot be read, Session1 fails
  `GetPlatformStatus` with a distinct error, and never guesses `enrolled`.
  This coupling (no status at all while sl-authd is down) is a known 0.0.3
  limitation, listed in the contract's deferred hardening items.
- The status carries no pairing code, key material, counters or session
  counts, per the contract. It also does not expose `reset-pending`.

## Properties provable by unit tests

These assume injected systemd, sl-authd and filesystem backends, and a
temporary directory.
- **Signatures:** each new method is zero-argument, and an argument is
  rejected with `InvalidArgs` before any permit is taken.
- **Sequences:**
  - the exact steps of Enable, Disable and Reenroll, and that each failure
    point in the matrices produces the listed error and stops there;
  - Reenroll never starts sl-remoted after a failed reset, rotation or
    pairing;
  - on a disabled machine, Reenroll creates no pairing and starts nothing.
- **Reset-pending:**
  - Enable returns `ResetIncomplete` while the marker exists, before any
    worker, sl-authd or systemd call;
  - the enable worker also refuses;
  - Reenroll clears the marker only as its final durable step, after the
    reset, rotation and pairing behavior succeeded, and before starting
    sl-remoted;
  - Reenroll holds the remote-management permit through the marker clear and
    the sl-remoted start attempt: a concurrent call during either is `Busy`,
    and the permit is released only when Reenroll returns, including when the
    start fails;
  - a failure at any earlier Reenroll step leaves the marker present;
  - neither Session1 nor `GetRemoteManagementEnrollment` exposes it.
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
  - generation-directory swap, with simulated failures leaving the previous
    state;
  - removal of stale temporary files and unreferenced generations;
  - the boot-reset step order, starting with the `reset-pending` commit and
    ending with its removal, with a failure at each step leaving the
    matrix's state;
  - no destructive action if the marker cannot be created.
- **Status 0.4 composition:** field sources, absence handling, and a distinct
  error (not a guessed value) when sl-authd fails.
- **Static assertions (image build):** the Platform1 bus policy for root and
  sl-console, the unit files, file contexts and ownership. Static only.

## Deferred to 5E (runtime; not claimed here)
- **Bus policy:** the installed policy admits exactly root and sl-console to
  the four methods under the real bus, and sl-remoted to none.
- **systemd:**
  - worker, stop, start and condition behavior under the real manager;
  - `Requires=` fail-closed when the boot reset fails.
- **SELinux:**
  - confinement of the worker, sl-remoted and sl-console domains;
  - the key readable only by sl-remoted.
- **TLS on the real system:**
  - `openssl` generation with the fixed argv and path in the real image;
  - the certificate contents;
  - the fingerprint matches what browsers display;
  - browser acceptance behavior.
- **Persistence:** the enabled marker and identity survive reboot and a
  deployment change.
- **Boot reset:**
  - the GRUB interrupt, edit and boot keys on the real console (serial and
    VGA);
  - the reset runs once and before sl-remoted, sl-console, sl-sessiond and
    sl-platformd;
  - the resulting state and failure tables above;
  - both reset-pending enforcement layers, as required checks:
    - Enable returns `ResetIncomplete`, with no side effects, on the real
      system;
    - sl-remoted's `!reset-pending` condition keeps it stopped at boot and on
      a direct start, across reboots, until repair.
- **`listening` accuracy:** the runtime file matches actual acceptance of
  connections.
- **Status consistency:** the fields common to schema 0.3 agree between
  Platform/corectl and Session1's schema 0.4. The complete statuses are not
  identical, because 0.4 adds `remote_management`.

## Accepted interpretations
1. Web sessions exist only in sl-remoted's memory, so stopping it
   invalidates them.
2. The optional pairing fields are expressed as `""` and `0` in a fixed
   `(ssst)` return.
3. A bootc deployment change does not alter the administrative state.
4. Schema 0.4 is produced by Session1; Platform's `GetStatus` stays 0.3.
5. Session1 reads `enabled` from the marker file, rather than through a fifth
   Platform method.

Reenroll on a disabled machine, previously an interpretation, is now a
contract amendment (see [remote-management-0.0.3.md](remote-management-0.0.3.md)).

## Resolved questions
1. **Menu window:** 1 second is accepted for 0.0.3. The operator must
   interrupt the menu during startup; the keys are verified in 5E. Replacing
   the trigger is a hardening item.
2. **Kernel argument:** `signallayer.remote-management-reset`.
3. **Failed reset:** sl-console must visibly report that a requested boot
   reset failed. The mechanism is defined in 5C-d. After the `reset-pending`
   commit, sl-console also learns of an incomplete reset through
   `ResetIncomplete`.
4. **Reboot during a sequence:** crash-equivalence is sufficient, and
   `StartReboot` does not refuse.
5. **sl-authd unavailable:** Session1 fails `GetPlatformStatus` with a
   distinct error rather than guessing `enrolled`. This is a known 0.0.3
   limitation, listed in the contract's hardening items.
6. **Addresses:** one `url`, as selected above.
7. **Timeouts:** 30 seconds for workers, 10 seconds for starting or stopping
   sl-remoted.
