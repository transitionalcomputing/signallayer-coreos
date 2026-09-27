# sl-authd interface (0.0.3)

**Status:** 5C-a frozen. Derived from the frozen
[0.0.3 remote management contract](remote-management-0.0.3.md); it changes no
contract decision. Every parameter below is frozen; the proposals and open
questions of step 1 were adopted and resolved in 5C-a step 2.

sl-authd owns only authentication state: the operator password hash, the
recovery-key hash, pending pairing state and attempt/backoff state. It answers
fixed authentication operations for fixed callers. It has no network listener,
no machine-mutation authority and no authorization-to-act role: callers decide
what a successful verification permits. sl-authd never creates a pairing by
itself; only an explicit local Enable, through Platform, does.

- System bus name: `org.signallayer.Auth1`
- Object path: `/org/signallayer/Auth1`
- Interface: `org.signallayer.Auth1`
- Error prefix: `org.signallayer.Auth1.Error.`

## State model

sl-authd is always in exactly one of four states.

| State | Password hash | Recovery-key hash | Confirmation deadline | Pending pairing (memory only) |
|---|---|---|---|---|
| **Unenrolled** | absent | absent | absent | absent |
| **PendingPairing** | absent | absent | absent | present and unexpired |
| **EnrolledUnconfirmed** | present (provisional) | present (provisional) | present | absent |
| **Enrolled** | present | present | absent | absent |

Backoff counters are kept in memory alongside and are not part of the state.

Transitions (the method names are defined below):

| From | Event or operation | To | Notes |
|---|---|---|---|
| Unenrolled | `EnsurePendingPairing` | PendingPairing | Creates a new code, a 10-minute expiry and a zero attempt count. |
| PendingPairing | `EnsurePendingPairing` | PendingPairing | No change while unexpired; the code is not rotated. |
| PendingPairing | pairing expiry reached | Unenrolled | Evaluated against `CLOCK_BOOTTIME` on each operation; no timer. |
| PendingPairing | fifth wrong `ConsumePairing` code | Unenrolled | The pending pairing is destroyed. A new code requires explicit local Enable. |
| PendingPairing | sl-authd restart | Unenrolled | The pending pairing exists only in memory. |
| PendingPairing | `CancelPendingPairing` | Unenrolled | Used by Platform's Disable. |
| PendingPairing | `ConsumePairing` (valid code, acceptable password) | EnrolledUnconfirmed | Durably commits the password hash, recovery-key hash and a confirmation deadline 10 minutes later, then returns the recovery key once. |
| EnrolledUnconfirmed | `ConfirmRecoveryKey` (matching key, before the deadline) | Enrolled | Durably removes the confirmation deadline. |
| EnrolledUnconfirmed | confirmation deadline reached | Unenrolled | The provisional password and recovery-key material is durably discarded. See "Normalization". |
| EnrolledUnconfirmed | `EnsurePendingPairing` before the deadline | EnrolledUnconfirmed | No-op. No pairing is created while a provisional enrollment exists. |
| EnrolledUnconfirmed | `EnsurePendingPairing` after the deadline | PendingPairing | First durably discards the provisional material, then creates a fresh pending pairing. This call is itself the explicit local Enable the contract requires. |
| EnrolledUnconfirmed | `CancelPendingPairing` | EnrolledUnconfirmed | No-op. It neither finalizes nor alters an unexpired provisional enrollment. |
| EnrolledUnconfirmed | sl-authd restart | EnrolledUnconfirmed | Persisted. A restart neither finalizes nor destroys it. |
| Enrolled | `RecoverPassword` (valid recovery key) | Enrolled | Replaces the password hash only. The recovery key stays valid. |
| Enrolled | `VerifyPassword` | Enrolled | Read-only apart from in-memory backoff accounting. |
| Enrolled | `EnsurePendingPairing` or `CancelPendingPairing` | Enrolled | No-op. The contract creates a pairing only when no operator is enrolled. |
| Any | `ResetEnrollment` | Unenrolled | Clears credentials, any provisional state and any pending pairing. |
| Unenrolled | `CancelPendingPairing` | Unenrolled | No-op. |

**Normalization.** An EnrolledUnconfirmed state whose confirmation deadline has
passed is normalized to Unenrolled before any operation is serviced, both at
startup and on each later operation. The cleanup is committed durably before
the operation proceeds. Normalization records, in memory, that the provisional
enrollment expired, so that a later `ConfirmRecoveryKey` returns
`ConfirmationExpired` rather than `NoProvisionalEnrollment`. The record is
cleared by the next state change (a new pairing, a reset or an enrollment) and
does not survive a further restart.

Re-enrollment is two separate operations composed by Platform:
`ResetEnrollment`, then `EnsurePendingPairing`. The boot-time reset uses
`ResetEnrollment` only. Pairing creation and reset remain separate operations.

## Methods

All methods are fixed. Their argument signatures are exact: a call with any
other signature, including any argument to a zero-argument method, is rejected
with `org.freedesktop.DBus.Error.InvalidArgs` before any state is read. This is
the zbus 5.19 zero-argument pattern already used by sl-platformd's
`CheckedPlatform`, extended to check every method's signature.

**Implementation-layer limitation:** zvariant represents a message body with
several arguments as a structure, so the check sees two string arguments and a
single `(ss)` structure argument as the same signature and accepts both. Both
deliver the same two strings. How the real bus and zbus handle a `(ss)` body at
runtime is a 5E claim.

### Check order
Each method applies its checks in this order and stops at the first failure:
1. **Admission** (methods that may need Argon2id work): `Busy`.
2. **Storage:** a corrupt or unknown state file gives `Unavailable` (except
   for `ResetEnrollment`); an expired provisional enrollment is normalized
   durably.
3. **Argument bounds:** any string argument longer than its fixed bound
   (1024 bytes for passwords, 64 bytes for pairing codes and recovery keys),
   and any pairing code or recovery key that is not well formed, gives
   `InvalidArgument`. Malformed values can never match, so they consume no
   attempt and change no counter.
4. **State:** the named state error.
5. **Backoff:** `RateLimited`, without evaluating the credential.
6. **Credential**, then **new-password rules**, then the durable commit.

A request waiting in the admission queue performs steps 2 to 6 only when it
runs, under the same serialization as every other operation, so no commit is
derived from state or backoff read before an earlier operation finished.

### Errors
Every invalid-state call has a named error; nothing is implicit.

| Error | Meaning |
|---|---|
| `NotEnrolled` | The operation needs Enrolled, but the state is Unenrolled or PendingPairing. |
| `EnrollmentUnconfirmed` | The operation is refused because a provisional enrollment (EnrolledUnconfirmed) exists. |
| `AlreadyEnrolled` | The operation needs a pending pairing, but the state is Enrolled. |
| `NoPendingPairing` | The operation needs PendingPairing, but the state is Unenrolled, or the pairing expired or was destroyed. |
| `InvalidPairingCode` | Wrong pairing code; attempts 1 to 4. |
| `PairingAttemptsExhausted` | The fifth wrong pairing code. The pending pairing has been destroyed. |
| `NoProvisionalEnrollment` | `ConfirmRecoveryKey` called when the state is not EnrolledUnconfirmed. |
| `ConfirmationExpired` | `ConfirmRecoveryKey` called after the confirmation deadline. The provisional material has been durably discarded. |
| `InvalidCredential` | Wrong password or recovery key. |
| `PasswordRejected` | The new password violates the password rules. |
| `RateLimited` | Backoff is active for this scope. The credential was not evaluated. |
| `Busy` | Argon2id admission is full. Returned before any failure counter or state transition. |
| `InvalidArgument` | An argument exceeds a fixed bound, for example a password longer than 1024 bytes. |
| `Unavailable` | State could not be read or written safely. No partial state change is visible. |

### VerifyPassword(s password) -> ()
- Verifies the enrolled operator password.
- **Errors:** `NotEnrolled`, `EnrollmentUnconfirmed`, `InvalidCredential`,
  `RateLimited`, `Busy`, `InvalidArgument`, `Unavailable`.
- A failure increments the sender's password counter; a success resets it.
- While backoff is active, the call is refused with `RateLimited` without
  evaluating the password.
- **Callers:** sl-remoted (web login), console UI (enrolled-console
  actions).

### ConsumePairing(s pairing_code, s new_password) -> (s recovery_key)
- Valid only in PendingPairing.
- On a matching code and an acceptable password, it durably commits
  EnrolledUnconfirmed: the Argon2id password hash, the Argon2id hash of a
  newly generated recovery key, and a confirmation deadline 10 minutes after
  this call. It removes the pending pairing, then returns the recovery key
  exactly once.
- A wrong code increments the pending pairing's attempt count. The fifth wrong
  code destroys the pending pairing and returns `PairingAttemptsExhausted`.
- **Errors:** `NoPendingPairing`, `AlreadyEnrolled`, `EnrollmentUnconfirmed`,
  `InvalidPairingCode`, `PairingAttemptsExhausted`, `PasswordRejected`, `Busy`,
  `InvalidArgument`, `Unavailable`.
- **Callers:** sl-remoted only. Pairing happens over HTTPS.

### ConfirmRecoveryKey(s recovery_key) -> ()
- Valid only in EnrolledUnconfirmed, before the confirmation deadline.
- On a matching key, durably moves to Enrolled.
- After the deadline, it first durably normalizes to Unenrolled, then returns
  `ConfirmationExpired`.
- A wrong key counts against the confirmation scope's backoff only; it never
  discards the provisional enrollment.
- sl-remoted calls it after the owner re-enters the recovery key shown at
  pairing.
- **Errors:** `NoProvisionalEnrollment`, `ConfirmationExpired`,
  `InvalidCredential`, `RateLimited`, `Busy`, `InvalidArgument`,
  `Unavailable`.
- **Callers:** sl-remoted only.

### RecoverPassword(s recovery_key, s new_password) -> ()
- Valid only in Enrolled.
- Verifies the recovery key and replaces only the password hash. The recovery
  key stays valid. Recovery-key rotation happens only through re-enrollment.
- **Errors:** `NotEnrolled`, `EnrollmentUnconfirmed`, `InvalidCredential`,
  `PasswordRejected`, `RateLimited`, `Busy`, `InvalidArgument`,
  `Unavailable`.
- **Callers:** console UI only. The contract places recovery at the console.

### EnsurePendingPairing() -> ()
Supports Platform's idempotent `EnableRemoteManagement`.

| State | Effect |
|---|---|
| Unenrolled | Creates a new pending pairing. |
| PendingPairing (unexpired) | No-op. The code is not rotated. |
| EnrolledUnconfirmed, before the deadline | No-op. |
| EnrolledUnconfirmed, after the deadline | Durably discards the provisional material, then creates a new pending pairing. |
| Enrolled | No-op. |

- It never touches credentials of an Enrolled operator or the TLS identity.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only.

### CancelPendingPairing() -> ()
- Removes a pending pairing.
- A no-op in Unenrolled and Enrolled.
- In EnrolledUnconfirmed, a no-op: it does not finalize or alter the
  provisional enrollment.
- Required by the contract's `DisableRemoteManagement`, which invalidates any
  pending pairing.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only.

### ResetEnrollment() -> ()
- From any state, clears the password hash, the recovery-key hash, any
  provisional state and confirmation deadline, and any pending pairing,
  returning to Unenrolled.
- After the durable reset succeeds, it clears every in-memory backoff counter
  (both password scopes, recovery and confirmation), and the pending pairing
  with its attempt count. A failed reset clears nothing.
- It never touches the TLS identity, which stays outside sl-authd.
- It is the only method that succeeds when the state file is corrupt or of an
  unknown version: it replaces it atomically with a clean, durable
  Unenrolled state.
- **Errors:** `Unavailable` (only if the clean state cannot be written).
- **Callers:** sl-platformd only, for Re-enroll and the boot-time reset
  worker.

### GetPendingPairing() -> (b pending, s pairing_code, t expires_at)
- Reports the unexpired pending pairing, if any.
- When `pending` is false (Unenrolled, EnrolledUnconfirmed or Enrolled),
  `pairing_code` is empty and `expires_at` is 0.
- `pairing_code` is the 8 canonical uppercase Crockford characters, without
  the display hyphen; Platform and the console format it as `XXXX-XXXX`.
- `expires_at` is Unix seconds (UTC).
- It never creates, extends or regenerates a pairing.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only. Platform composes
  `GetRemoteManagementEnrollment` from this result, together with the URL and
  TLS fingerprint it owns.

### GetEnrollmentState() -> (b enrolled, b pairing_pending)

| State | Returns |
|---|---|
| Unenrolled | (false, false) |
| PendingPairing | (false, true) |
| EnrolledUnconfirmed | (false, false) |
| Enrolled | (true, false) |

- It reports facts only, with no secrets or counters.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd (Enable logic) and sl-sessiond (status schema 0.4
  `enrolled`, aggregated by Session1). The console UI reads enrollment state
  through Session1, not directly.

## Boundary rules
- sl-authd knows only pairing and authentication state. It never knows the
  console URL, addresses or the TLS certificate or fingerprint.
- Platform composes `GetRemoteManagementEnrollment()` as (url, fingerprint)
  from Platform-owned state, plus (pairing_code, expires_at) from
  `GetPendingPairing`.
- The TLS identity is generated, stored and rotated outside sl-authd.
- Creating a pending pairing (`EnsurePendingPairing`) and resetting enrollment
  (`ResetEnrollment`) are separate operations.
- sl-authd never creates a pairing by itself.
- Platform never reads or writes sl-authd's files; it uses these methods only.
- sl-authd returns no secret except the recovery key once, from
  `ConsumePairing`, and the pending pairing code, from `GetPendingPairing`, to
  Platform only.

## Caller matrix and bus policy

| Method | sl-remoted | sl-console | sl-platformd (root) | sl-sessiond |
|---|---|---|---|---|
| VerifyPassword | yes | yes | no | no |
| ConsumePairing | yes | no | no | no |
| ConfirmRecoveryKey | yes | no | no | no |
| RecoverPassword | no | yes | no | no |
| EnsurePendingPairing | no | no | yes | no |
| CancelPendingPairing | no | no | yes | no |
| ResetEnrollment | no | no | yes | no |
| GetPendingPairing | no | no | yes | no |
| GetEnrollmentState | no | no | yes | yes |

`org.signallayer.Auth1.conf` follows `Session1.conf` and `Platform1.conf`:
- An SELinux `associate` of `org.signallayer.Auth1` with `sl_authd_t`.
- The default context denies ownership and every `send_destination` to
  `org.signallayer.Auth1`.
- `<policy user="sl-authd">` allows `own` only.
- One `<policy user="…">` block per caller, each allowing exactly its methods
  on the exact destination, path and interface.
- No wildcard members and no introspection allowance.

**Limit of UID policy:** sl-platformd runs as root, so the `user="root"` rules
admit any root process, not only sl-platformd. Restricting the Platform-only
methods to sl-platformd itself is deferred to the hardening release; see below.

## Parameters

### Hashing (frozen)
- The password and the recovery key are both hashed with **Argon2id,
  m = 64 MiB (65536 KiB), t = 3, p = 1**. There is no second hash function.
- Hashes are stored as PHC strings, so the parameters travel with each hash.
- A 16-byte random salt and a 32-byte output.

### Argon2id admission (frozen)
- Admission is bounded: one active hash plus a small bounded queue. Requests
  beyond the queue receive `Busy`.
- An admission failure happens before any failure counter or state
  transition, so `Busy` never counts as a wrong credential.
- `Busy` is listed on every method that may need Argon2id work:
  `VerifyPassword`, `ConsumePairing`, `ConfirmRecoveryKey` and
  `RecoverPassword`.
- A queue of 4, allowing at most 5 hashes admitted at once. This
  bounds peak Argon2id memory to one active 64 MiB computation, while the
  small queue absorbs a login and a console action arriving together.

### Password rules (frozen)
- At least 12 Unicode code points and at most 1024 bytes of UTF-8.
- No composition rules.
- Reject invalid UTF-8; apply no Unicode normalization; reject a password
  equal to the pairing code or recovery key. "Equal" means the password would
  be accepted as that code (case-insensitively, with or without the hyphen) or
  that key (ignoring ASCII case).

### Pairing code (frozen)
- 8 characters from Crockford base32 (40 bits), generated from the kernel
  CSPRNG.
- Expires 10 minutes after creation, and is single-use.
- The fifth wrong attempt destroys the pending pairing. A new code requires
  explicit local Enable.
- The plaintext code is held in sl-authd's memory only, never on disk. An
  sl-authd restart drops a pending pairing.
- Displayed as `XXXX-XXXX` and accepted case-insensitively, with or without
  the hyphen.

### Recovery key (frozen)
- 128 bits from the kernel CSPRNG, hashed with Argon2id as above.
- It stays valid through `RecoverPassword`. Rotation happens only through
  re-enrollment.
- **Canonical encoding:** the 128 bits, most significant bit first, as 26
  uppercase Crockford base32 characters. The first 25 characters carry 125
  bits; the final character carries the last 3 key bits in its high 3 bits,
  and its low 2 bits are zero padding. Any non-canonical encoding is rejected:
  nonzero padding bits, a character outside the uppercase Crockford alphabet,
  or a length other than 26. Clients may display the key in groups, but they
  submit the canonical 26-character form.

### Confirmation deadline (frozen)
10 minutes after `ConsumePairing`.

### Clock sources (frozen)
- **In-memory timers** (pairing expiry and backoff windows) use
  `CLOCK_BOOTTIME` through the injected clock: monotonic, and including time
  spent in system suspend. They never use wall-clock time, so wall-clock
  steps neither extend nor shorten them.
- **The persisted confirmation deadline** is wall-clock Unix seconds, because
  it must survive a restart. A stored deadline more than 10 minutes after the
  current wall time cannot have been set by a fresh enrollment, so it is
  treated as expired and normalized.
- `GetPendingPairing` reports `expires_at` as the wall-clock time at creation
  plus 10 minutes; the expiry itself is decided on `CLOCK_BOOTTIME`.
- If `CLOCK_BOOTTIME` cannot be read, the operation returns `Unavailable`. The clock is read before the backoff check, so the credential is normally never evaluated. Only if the read fails after a wrong credential was evaluated is that attempt recorded: the scope's failure count is incremented, its last-failure time is left unchanged, and the reply is `Unavailable`, not `InvalidCredential`.
- Behavior of these clocks on the real VM and runtime is verified in 5E.

### Backoff (frozen)
- Counters are **memory-only** for 0.0.3. They reset when sl-authd restarts.
- The password scope (web or console) comes from the authenticated D-Bus
  sender identity, never from a caller-supplied value: sl-remoted's
  identity maps to the web scope and the console UI's identity to the console
  scope.
- Pairing is its own scope, because it is a separate fixed method
  (`ConsumePairing`), and it is also bounded by the five-attempt destruction
  rule.
- `RecoverPassword` has its own recovery scope and `ConfirmRecoveryKey` its
  own confirmation scope, each keyed by the fixed method.
- After 5 consecutive failures in a scope, delay 2^(n−5) seconds, capped at 15
  minutes. A success resets that scope.
- `RateLimited` carries no machine-readable retry-after in 0.0.3. Clients show
  a generic "try again later" message.
- Wrong `ConfirmRecoveryKey` attempts are subject to the confirmation scope's
  backoff only. They never discard the provisional enrollment, which ends only
  at its deadline, on reset or on successful confirmation.

### Service identities (frozen)
The console UI's service identity is `sl-console`. It is the bus-policy user
for the console's methods and maps to the console password scope;
`sl-remoted` maps to the web password scope.

### Randomness (frozen)
Use the kernel CSPRNG through `libc::getrandom`, blocking until the pool is
initialized. No new crate is needed, because `libc` is already a workspace
dependency.

## Storage

### Location and ownership
- **Directory:** `/var/lib/sl-authd`, created by systemd `StateDirectory=sl-authd`.
  It is owned by `sl-authd:sl-authd`, mode 0700, and persists across bootc
  deployments.
- **State file:** one file, `/var/lib/sl-authd/state.json`, mode 0600,
  containing:
  - a format version;
  - the state (Unenrolled, EnrolledUnconfirmed or Enrolled);
  - the password PHC hash;
  - the recovery-key PHC hash;
  - the confirmation deadline, in EnrolledUnconfirmed only.
- **Never in `state.json`:** backoff counters or timestamps, and the plaintext
  pending pairing code. PendingPairing is never persisted.
- **SELinux:** a dedicated file type, for example `sl_authd_var_lib_t`,
  writable only by `sl_authd_t`. This would be the first persistent SignalLayer
  service state. Existing services keep none.

### Atomic writes and crash semantics
- **Write sequence:**
  1. Write a new temporary file in the same directory (`O_CREAT|O_EXCL`,
     mode 0600).
  2. `fsync` it.
  3. `rename` it over `state.json`.
  4. `fsync` the directory.
- **After a crash,** either the old or the new state is visible, never a
  mixture. Stale temporary files are removed at startup.
- **An unreadable or unknown state file** makes sl-authd refuse every operation
  with `Unavailable` rather than silently reset, with one exception:
  `ResetEnrollment` may replace the invalid state with a clean, durable
  Unenrolled state, using the same atomic-write sequence. Recovery from
  corruption is therefore the boot-time reset (or an explicit re-enrollment).
- **A method returns success only after its commit is durable.**
- **EnrolledUnconfirmed persists** its password hash, recovery-key hash and
  confirmation deadline, so an sl-authd restart neither silently finalizes nor
  destroys a provisional enrollment.
- **An expired persisted provisional enrollment** is normalized to Unenrolled
  at startup or before the first operation is serviced, with the cleanup
  committed durably.

### Enrollment commit point and recovery-key delivery (decided)
`ConsumePairing` durably commits **EnrolledUnconfirmed** before it returns the
recovery key. The key's delivery path is the D-Bus reply to sl-remoted,
then the HTTPS response to the browser. Enrollment becomes final only when
`ConfirmRecoveryKey` proves the owner holds the key.

If delivery fails, because sl-remoted crashes, the connection drops or the
page is closed, the provisional enrollment is discarded at its deadline. The
owner then invokes Enable again locally, which creates a fresh pairing. No
enrollment ever exists without proof that the owner holds the recovery key. The
recovery key is held in memory only between generation and the reply, and is
never logged.

Considered, not chosen:
- **Commit and return:** enrollment final at commit, so a lost key is silently
  lost.
- **Confirmed, with a password-authenticated reissue:** would add methods and
  let a password holder replace the recovery key.
- **Password-authenticated regeneration at any time:** would make the recovery
  key no longer independent of the password.

## Security properties provable by unit tests
Using an injected clock, an injected random source and a temporary state
directory:
- **State machine:** every transition in the tables above, and that no other
  transition is possible, including every named error for every
  invalid-state call.
- **Provisional enrollment:**
  - `ConsumePairing` reaches EnrolledUnconfirmed, not Enrolled;
  - `ConfirmRecoveryKey` finalizes only on a matching key before the deadline;
  - after the deadline, the provisional material is discarded durably, both at
    startup normalization and on the next operation;
  - a simulated restart preserves an unexpired provisional enrollment without
    finalizing it.
- **In EnrolledUnconfirmed:**
  - `GetEnrollmentState` returns (false, false);
  - `GetPendingPairing` reports no pairing;
  - `EnsurePendingPairing` is a no-op before the deadline and discards the
    material, then creates a pairing, after it;
  - `CancelPendingPairing` doesn't alter it;
  - `ResetEnrollment` clears it;
  - `VerifyPassword` and `RecoverPassword` return `EnrollmentUnconfirmed`.
- **Pairing:** 8-character Crockford base32 codes from the injected source;
  single-use; refused after 10 minutes; the fifth wrong code destroys the
  pairing with `PairingAttemptsExhausted`; the plaintext code never appears in
  `state.json`; a simulated restart drops a pending pairing.
- **Recovery:** `RecoverPassword` replaces only the password hash, and the same
  recovery key still verifies afterwards.
- **Backoff:**
  - the scope is derived from the sender identity, and a caller-supplied value
    has no effect;
  - the scopes are independent;
  - counters are absent from `state.json` and reset on a simulated restart;
  - `ResetEnrollment` leaves every scope clean;
  - wall-clock steps backward and forward change no in-memory window, and a
    far-future persisted deadline normalizes as expired.
- **Admission:** beyond one active hash plus the queue, calls return `Busy`
  without changing any counter or state.
- **Hashing:** both hashes are Argon2id with m = 65536, t = 3, p = 1, as
  recorded in the stored PHC string.
- **Formats:** password bounds (12 code points to 1024 bytes); the recovery key
  has 128 bits from the injected source.
- **Storage:** atomic-write behavior, where simulated failures before rename
  leave the old state intact; an unknown or corrupt file yields `Unavailable`
  for every operation except `ResetEnrollment`, which produces a clean,
  durable Unenrolled state.
- **Secrecy:** no secret (password, code or key) appears in logs or error
  messages; comparisons of codes are constant-time.
- **Signatures:** wrong signatures, including arguments to zero-argument
  methods, are rejected with `InvalidArgs`.

## Runtime properties deferred to 5E
Not provable by unit tests, and not claimed here:
- the installed D-Bus policy admits exactly the caller matrix, and sender
  identities map to the intended backoff scopes under the real bus;
- SELinux confinement of `sl_authd_t` and labeling of `/var/lib/sl-authd`;
- systemd `StateDirectory` ownership, mode and hardening under the real unit;
- restart behavior of the real service: a pending pairing is dropped, an
  unexpired provisional enrollment is preserved, an expired one is normalized,
  and counters reset;
- the boot-time reset worker's ordering relative to sl-authd;
- journal logging of authentication events with no secrets;
- behavior under memory pressure and `Busy` admission.

## Deferred to the hardening release
- Recovery-key rotation on use.
- Restart-resistant (persistent) throttling.
- Zeroizing secrets (passwords, pairing code, recovery key) in memory after
  use.
- SELinux-level restriction of the Platform-only methods to sl-platformd,
  since UID-based bus policy admits any root process.

## Dependency workflow for step 2
- **Argon2id:** add the RustCrypto `argon2` crate. `Cargo.lock` is regenerated
  in a rootless container from the public
  `ghcr.io/transitionalcomputing/signallayer-base` (`dnf install cargo`), with
  network access, and the regenerated lock is committed. The image build
  already fetches crates under `--locked`.
- **CSPRNG:** `libc::getrandom`, with no new crate.

## Resolved questions (5C-a step 2)
1. **`RateLimited` retry-after:** none in 0.0.3; clients show a generic
   message.
2. **Boot-time reset ordering:** sl-authd must be available before the reset
   worker runs, and the reset must complete before sl-remoted or
   sl-console expose enrollment state. The mechanics belong to 5C-b and are
   proven in 5E.
3. **Console UI service identity:** `sl-console`.
4. **Wrong `ConfirmRecoveryKey` attempts:** backoff only; they never discard
   the provisional enrollment.
