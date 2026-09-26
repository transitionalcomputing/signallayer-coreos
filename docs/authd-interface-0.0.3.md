# sl-authd interface (0.0.3)

**Status:** 5C-a frozen. Derived from the frozen
[0.0.3 remote management contract](remote-management-0.0.3.md); it changes no
contract decision. Items still marked **proposal** below were not decided in
5C-a and remain open for review. Everything else is frozen.

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
| PendingPairing | pairing expiry reached | Unenrolled | Evaluated against the clock on each operation; no timer. |
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
the operation proceeds.

Re-enrollment is two separate operations composed by Platform:
`ResetEnrollment`, then `EnsurePendingPairing`. The boot-time reset uses
`ResetEnrollment` only. Pairing creation and reset remain separate operations.

## Methods

All methods are fixed. Their argument signatures are exact: a call with any
other signature, including any argument to a zero-argument method, is rejected
with `org.freedesktop.DBus.Error.InvalidArgs` before any state is read. This is
the zbus 5.19 zero-argument pattern already used by sl-platformd's
`CheckedPlatform`.

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
- **Callers:** sl-managementd (web login), console UI (enrolled-console
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
- **Callers:** sl-managementd only. Pairing happens over HTTPS.

### ConfirmRecoveryKey(s recovery_key) -> ()
- Valid only in EnrolledUnconfirmed, before the confirmation deadline.
- On a matching key, durably moves to Enrolled.
- sl-managementd calls it after the owner re-enters the recovery key shown at
  pairing.
- **Errors:** `NoProvisionalEnrollment`, `ConfirmationExpired`,
  `InvalidCredential`, `RateLimited`, `Busy`, `InvalidArgument`,
  `Unavailable`.
- **Callers:** sl-managementd only.

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
- It never touches the TLS identity, which stays outside sl-authd.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only, for Re-enroll and the boot-time reset
  worker.

### GetPendingPairing() -> (b pending, s pairing_code, t expires_at)
- Reports the unexpired pending pairing, if any.
- When `pending` is false (Unenrolled, EnrolledUnconfirmed or Enrolled),
  `pairing_code` is empty and `expires_at` is 0.
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

| Method | sl-managementd | console UI | sl-platformd (root) | sl-sessiond |
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
- **Proposal:** a 16-byte random salt and a 32-byte output.

### Argon2id admission (frozen, with a proposed size)
- Admission is bounded: one active hash plus a small bounded queue. Requests
  beyond the queue receive `Busy`.
- An admission failure happens before any failure counter or state
  transition, so `Busy` never counts as a wrong credential.
- `Busy` is listed on every method that may need Argon2id work:
  `VerifyPassword`, `ConsumePairing`, `ConfirmRecoveryKey` and
  `RecoverPassword`.
- **Proposal:** a queue of 4, allowing at most 5 hashes admitted at once. This
  bounds peak Argon2id memory to one active 64 MiB computation, while the
  small queue absorbs a login and a console action arriving together.

### Password rules (frozen)
- At least 12 Unicode code points and at most 1024 bytes of UTF-8.
- No composition rules.
- **Proposal:** reject invalid UTF-8; apply no Unicode normalization; reject a
  password equal to the pairing code or recovery key.

### Pairing code (frozen)
- 8 characters from Crockford base32 (40 bits), generated from the kernel
  CSPRNG.
- Expires 10 minutes after creation, and is single-use.
- The fifth wrong attempt destroys the pending pairing. A new code requires
  explicit local Enable.
- The plaintext code is held in sl-authd's memory only, never on disk. An
  sl-authd restart drops a pending pairing.
- **Proposal:** display it as `XXXX-XXXX` and accept it case-insensitively,
  with or without the hyphen.

### Recovery key (frozen)
- 128 bits from the kernel CSPRNG, hashed with Argon2id as above.
- It stays valid through `RecoverPassword`. Rotation happens only through
  re-enrollment.
- **Proposal:** encode it as 26 Crockford base32 characters, displayed in
  groups.

### Confirmation deadline (frozen)
10 minutes after `ConsumePairing`.

### Backoff (frozen scope, proposed schedule)
- Counters are **memory-only** for 0.0.3. They reset when sl-authd restarts.
- The password scope (web or console) comes from the authenticated D-Bus
  sender identity, never from a caller-supplied value: sl-managementd's
  identity maps to the web scope and the console UI's identity to the console
  scope.
- Pairing is its own scope, because it is a separate fixed method
  (`ConsumePairing`), and it is also bounded by the five-attempt destruction
  rule.
- **Proposal:** `RecoverPassword` has its own recovery scope and
  `ConfirmRecoveryKey` its own confirmation scope, each keyed by the fixed
  method.
- **Proposal:** after 5 consecutive failures in a scope, delay 2^(n−5)
  seconds, capped at 15 minutes. A success resets that scope.

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
  with `Unavailable` rather than silently reset. Recovery from corruption is
  the boot-time reset.
- **A method returns success only after its commit is durable.**
- **EnrolledUnconfirmed persists** its password hash, recovery-key hash and
  confirmation deadline, so an sl-authd restart neither silently finalizes nor
  destroys a provisional enrollment.
- **An expired persisted provisional enrollment** is normalized to Unenrolled
  at startup or before the first operation is serviced, with the cleanup
  committed durably.

### Enrollment commit point and recovery-key delivery (decided)
`ConsumePairing` durably commits **EnrolledUnconfirmed** before it returns the
recovery key. The key's delivery path is the D-Bus reply to sl-managementd,
then the HTTPS response to the browser. Enrollment becomes final only when
`ConfirmRecoveryKey` proves the owner holds the key.

If delivery fails, because sl-managementd crashes, the connection drops or the
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
  - counters are absent from `state.json` and reset on a simulated restart.
- **Admission:** beyond one active hash plus the queue, calls return `Busy`
  without changing any counter or state.
- **Hashing:** both hashes are Argon2id with m = 65536, t = 3, p = 1, as
  recorded in the stored PHC string.
- **Formats:** password bounds (12 code points to 1024 bytes); the recovery key
  has 128 bits from the injected source.
- **Storage:** atomic-write behavior, where simulated failures before rename
  leave the old state intact; an unknown or corrupt file yields `Unavailable`.
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
- SELinux-level restriction of the Platform-only methods to sl-platformd,
  since UID-based bus policy admits any root process.

## Dependency workflow for step 2
- **Argon2id:** add the RustCrypto `argon2` crate. `Cargo.lock` is regenerated
  in a rootless container from the public
  `ghcr.io/transitionalcomputing/signallayer-base` (`dnf install cargo`), with
  network access, and the regenerated lock is committed. The image build
  already fetches crates under `--locked`.
- **CSPRNG:** `libc::getrandom`, with no new crate.

## Open questions
1. **`RateLimited` retry-after:** carry it in the error message text, or as a
   typed value, for example a separate method or a changed return type?
2. **Boot-time reset ordering:** the contract routes the reset through a
   Platform early-boot worker calling sl-authd's methods, so sl-authd must run
   before that worker. Confirm the ordering and that sl-authd tolerates early
   start.
3. **Console UI service identity name** for the bus policy and the console
   backoff scope.
4. **Wrong `ConfirmRecoveryKey` attempts:** is the confirmation scope's backoff
   enough, or should repeated wrong keys also discard the provisional
   enrollment before its deadline?
