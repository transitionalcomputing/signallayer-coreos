# sl-authd interface (0.0.3)

**Status:** 5C-a draft for review. Derived from the frozen
[0.0.3 remote management contract](remote-management-0.0.3.md); it changes no
contract decision. Every parameter value below is a **5C-a design proposal
requiring review**, not a frozen decision.

sl-authd owns only authentication state: the operator password hash, the
recovery-key hash, pending pairing state and attempt/backoff state. It answers
fixed authentication operations for fixed callers. It has no network listener,
no machine-mutation authority and no authorization-to-act role: callers decide
what a successful verification permits.

- System bus name: `org.signallayer.Auth1`
- Object path: `/org/signallayer/Auth1`
- Interface: `org.signallayer.Auth1`
- Error prefix: `org.signallayer.Auth1.Error.`

## State model

sl-authd is always in exactly one of three states.

| State | Password hash | Recovery-key hash | Pending pairing |
|---|---|---|---|
| **Unenrolled** | absent | absent | absent, or expired (treated as absent) |
| **Pending pairing** | absent | absent | present and unexpired |
| **Enrolled** | present | present | absent |

Backoff state is kept alongside and is not a separate state.

Transitions (the method names are defined below):

| From | Operation | To | Notes |
|---|---|---|---|
| Unenrolled | `EnsurePendingPairing` | Pending pairing | Creates a new code and expiry. |
| Pending pairing | `EnsurePendingPairing` | Pending pairing | No change while unexpired; the code is not rotated. |
| Pending pairing | expiry reached | Unenrolled | Evaluated on each operation against the clock; no timer. |
| Pending pairing | `ConsumePairing` (valid code, acceptable password) | Enrolled | The recovery key is generated and returned once. |
| Pending pairing | `CancelPendingPairing` | Unenrolled | Used by Platform's Disable. |
| Enrolled | `EnsurePendingPairing` | Enrolled | No-op: the contract creates a pairing only when no operator is enrolled. |
| Enrolled | `RecoverPassword` (valid recovery key) | Enrolled | Replaces the password hash only. |
| Enrolled | `VerifyPassword` | Enrolled | Read-only apart from backoff accounting. |
| Any | `ResetEnrollment` | Unenrolled | Clears credentials and any pending pairing. |
| Unenrolled | `CancelPendingPairing` | Unenrolled | No-op. |

The contract's re-enrollment is two separate operations composed by Platform:
`ResetEnrollment`, then `EnsurePendingPairing`. The boot-time reset uses
`ResetEnrollment` only. The two are deliberately kept separate.

## Methods

All methods are fixed. Their argument signatures are exact: a call with any
other signature, including any argument to a zero-argument method, is rejected
with `org.freedesktop.DBus.Error.InvalidArgs` before any state is read. This is
the zbus 5.19 zero-argument pattern already used by sl-platformd's
`CheckedPlatform`.

Common errors:
- `Unavailable`: state could not be read or written safely. No partial state
  change is visible.
- `InvalidArgument`: an argument exceeds a fixed bound, for example a password
  longer than the maximum.

### VerifyPassword(s password) -> ()
Verifies the operator password.
- **Errors:** `NotEnrolled`, `InvalidCredential`, `RateLimited`,
  `InvalidArgument`, `Unavailable`.
- A failure increments the caller's backoff counter; a success resets it.
- While backoff is active, the call is refused with `RateLimited` **without
  evaluating the password**.
- **Callers:** sl-managementd (web login), console UI (enrolled-console
  actions).

### ConsumePairing(s pairing_code, s new_password) -> (s recovery_key)
Consumes the pending pairing and establishes enrollment.
- In one state commit, it validates the code and the password rules, stores the
  Argon2id password hash, generates a recovery key, stores its hash, and
  removes the pending pairing.
- It returns the recovery key exactly once. It is never retrievable again.
- **Errors:** `NoPendingPairing` (including expired), `InvalidPairingCode`,
  `PasswordRejected` (password rules), `AlreadyEnrolled`, `RateLimited`,
  `InvalidArgument`, `Unavailable`.
- A wrong code counts toward pairing backoff; see Parameters for invalidation
  after repeated failures.
- **Callers:** sl-managementd only. Pairing happens over HTTPS.
- See Storage for the commit-point and delivery analysis.

### RecoverPassword(s recovery_key, s new_password) -> ()
Replaces the password hash when the recovery key verifies.
- It changes authentication state only.
- Whether the recovery key is rotated on use is an open question.
- **Errors:** `NotEnrolled`, `InvalidCredential`, `PasswordRejected`,
  `RateLimited`, `InvalidArgument`, `Unavailable`.
- **Callers:** console UI only. The contract places recovery at the console.

### EnsurePendingPairing() -> ()
Supports Platform's idempotent `EnableRemoteManagement`.
- If enrolled: no-op.
- If a pending pairing exists and is unexpired: no-op, and the code is not
  rotated.
- Otherwise: creates a new pending pairing with a fresh code and expiry.
- It never touches credentials or the TLS identity.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only.

### CancelPendingPairing() -> ()
Removes any pending pairing.
- A no-op if none exists or if enrolled.
- **Derived requirement:** the contract's `DisableRemoteManagement`
  "invalidates … any pending pairing", and Platform may act on sl-authd only
  through fixed methods.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only.

### ResetEnrollment() -> ()
Clears the password hash, the recovery-key hash and any pending pairing,
returning to Unenrolled.
- Whether it also clears backoff state is an open question.
- It never touches the TLS identity, which stays outside sl-authd.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only, for Re-enroll and the boot-time reset
  worker.

### GetPendingPairing() -> (b pending, s pairing_code, t expires_at)
Reports the unexpired pending pairing, if any.
- When `pending` is false, `pairing_code` is empty and `expires_at` is 0.
- `expires_at` is Unix seconds (UTC).
- It **never creates, extends or regenerates** a pairing.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd only. Platform composes
  `GetRemoteManagementEnrollment` from this result, together with the URL and
  TLS fingerprint it owns.

### GetEnrollmentState() -> (b enrolled, b pairing_pending)
Reports facts only, with no secrets or counters.
- **Errors:** `Unavailable`.
- **Callers:** sl-platformd (Enable logic), console UI (unenrolled versus
  enrolled display), and sl-sessiond.
- **Derived requirement:** the contract defines status schema 0.4 `enrolled`
  as "sl-authd holds an enrolled operator credential", aggregated by Session1.
  sl-sessiond must therefore read this fact from sl-authd. See Open questions.

## Boundary rules
- sl-authd knows only pairing and authentication state. It never knows the
  console URL, addresses or the TLS certificate or fingerprint.
- Platform composes `GetRemoteManagementEnrollment()` as (url, fingerprint)
  from Platform-owned state, plus (pairing_code, expires_at) from
  `GetPendingPairing`.
- The TLS identity is generated, stored and rotated outside sl-authd.
- Creating a pending pairing (`EnsurePendingPairing`) and resetting enrollment
  (`ResetEnrollment`) are separate operations. The frozen contract doesn't
  require combining them.
- Platform never reads or writes sl-authd's files; it uses these methods only.
- sl-authd returns no secret except the recovery key once, from
  `ConsumePairing`, and the pending pairing code, from `GetPendingPairing`, to
  Platform only.

## Caller matrix and bus policy

| Method | sl-managementd | console UI | sl-platformd (root) | sl-sessiond |
|---|---|---|---|---|
| VerifyPassword | yes | yes | no | no |
| ConsumePairing | yes | no | no | no |
| RecoverPassword | no | yes | no | no |
| EnsurePendingPairing | no | no | yes | no |
| CancelPendingPairing | no | no | yes | no |
| ResetEnrollment | no | no | yes | no |
| GetPendingPairing | no | no | yes | no |
| GetEnrollmentState | no | yes | yes | yes |

Proposed `org.signallayer.Auth1.conf`, following `Session1.conf` and
`Platform1.conf`:
- An SELinux `associate` of `org.signallayer.Auth1` with `sl_authd_t`.
- The default context denies ownership and every `send_destination` to
  `org.signallayer.Auth1`.
- `<policy user="sl-authd">` allows `own` only.
- One `<policy user="…">` block per caller, each allowing exactly its methods
  on the exact destination, path and interface.
- No wildcard members and no introspection allowance.

The console UI's service user name is not yet fixed (for example `sl-console`).

**Limit of UID policy:** sl-platformd runs as root, so the `user="root"` rules
admit any root process, not just sl-platformd. Restricting the Platform-only
methods to sl-platformd itself needs SELinux `dbus send_msg` rules
(`sl_platformd_t` → `sl_authd_t`, and none for other domains). That is a 5E
runtime property.

## Parameters (5C-a design proposals, requiring review)

### Argon2id (password hash)
- **Proposal:** m = 64 MiB (65536 KiB), t = 3, p = 1; 16-byte random salt;
  32-byte output; stored as a PHC string, so the parameters travel with the
  hash and can be raised later.
- **Rationale:** RFC 9106's second recommended option is 64 MiB with t = 3.
  p = 1 bounds CPU on small VMs. OWASP's floor (19 MiB, t = 2, p = 1) is lower.
  Expect a few hundred milliseconds per verification on the development host.
  That hasn't been measured.
- **Trade-off:** each verification allocates 64 MiB. Concurrent verifications
  multiply memory use, so the proposal also serializes verifications inside
  sl-authd. That caps memory at the cost of queueing. A smaller m, such as
  19 MiB, is kinder to small machines but weaker against offline cracking of a
  stolen state file.

### Password rules
- **Proposal:** at least 12 Unicode code points; at most 1024 bytes of UTF-8;
  no composition rules; must not equal the pairing code or recovery key; no
  normalization beyond rejecting invalid UTF-8.
- **Rationale:** NIST SP 800-63B favors length over composition. There is a
  single operator reachable over the LAN, and the maximum bounds Argon2
  input and D-Bus message size.
- **Trade-off:** 12 is stricter than NIST's minimum of 8, which costs operator
  convenience. Leaving out Unicode normalization means visually identical
  passwords typed differently won't match; adding NFC normalization would fix
  that but needs care. A breached-password blocklist is out of scope for
  0.0.3.

### Pairing code
- **Proposal:** 8 characters from Crockford base32 (40 bits), displayed as
  `XXXX-XXXX` and accepted case-insensitively without the hyphen; generated
  from the kernel CSPRNG; valid for 10 minutes; single-use; invalidated after
  5 wrong attempts, after which Enable must be invoked again.
- **Rationale:** it can be typed from a console screen. 40 bits with a
  5-attempt cap makes online guessing negligible.
- **Trade-off:** a 6-digit numeric code (about 20 bits) is easier to type but
  depends entirely on the attempt cap. A longer expiry helps slow operators
  but lengthens the first-owner window.
- **Storage:** because Platform's `GetRemoteManagementEnrollment` must show
  the code again while it is pending, sl-authd must keep it retrievable, not
  only as a hash. See Open questions for memory-only versus at-rest storage.

### Recovery key
- **Proposal:** 128 random bits, encoded as 26 Crockford base32 characters and
  displayed in groups of four or five; generated from the kernel CSPRNG.
- **Storage proposal:** Argon2id with the same parameters, for one uniform
  mechanism.
- **Trade-off:** because the key is high-entropy, a fast keyed hash (for
  example HMAC-SHA-256 with a stored salt) would resist offline attack equally
  well and cost less memory and time. Argon2id would be uniformity rather than
  a security necessity.

### Backoff
- **Proposal:**
  - Separate counters for the web (sl-managementd) and the console UI, and a
    separate counter per pairing.
  - After 5 consecutive failures on a counter, delay 2^(n−5) seconds, capped at
    15 minutes.
  - A success resets that counter.
  - Counters persist across sl-authd restarts, so restarting doesn't bypass
    them.
- **Rationale:** separate counters stop a LAN attacker who fails web logins
  from locking out the console, which is the recovery path. Persistence stops
  restart-based bypass.
- **Trade-off:**
  - Persistence lets an on-link attacker keep the web path locked out,
    although the console path is unaffected.
  - Not persisting weakens the limit if sl-authd can be made to restart.
  - sl-authd can't see client addresses, so per-source limiting would have to
    live in sl-managementd.
  - Whether `ResetEnrollment` clears counters is open.

### Randomness
Use the kernel CSPRNG through `getrandom(2)`, blocking until the pool is
initialized. Never use a userspace PRNG seeded ad hoc.

## Storage

### Location and ownership
- **Directory:** `/var/lib/sl-authd`, created by systemd `StateDirectory=sl-authd`.
  It is owned by `sl-authd:sl-authd`, mode 0700, and persists across bootc
  deployments.
- **State file:** one file, `/var/lib/sl-authd/state.json`, mode 0600,
  containing:
  - a format version;
  - the password PHC hash;
  - the recovery-key hash;
  - backoff counters and timestamps;
  - the pending pairing, if storage at rest is chosen.
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

### Enrollment commit point and one-time recovery-key delivery
`ConsumePairing` must commit enrollment durably before it returns the recovery
key. Otherwise a crash could return a key for an enrollment that doesn't exist.
But once committed, the key's only delivery path is the D-Bus reply to
sl-managementd and then the HTTPS response to the browser. If sl-managementd
crashes, the connection drops or the page is closed, the owner has a working
password and no recovery key. The only remedy left is the boot-time reset.

Candidate designs, for review. None is chosen here.

1. **Commit and return (simplest).** Enrollment is final at commit, and a lost
   key is lost.
   - **Pro:** minimal state and methods.
   - **Con:** silent loss of recovery ability, discovered only when recovery is
     needed.
2. **"Recovery key pending delivery" state.** `ConsumePairing` commits
   Enrolled with a `recovery_unconfirmed` flag and returns the key. A new
   `ConfirmRecoveryKey(s recovery_key)`, called by sl-managementd after the
   owner re-enters the key, clears the flag. While the flag is set, the web UI
   forces a key re-issue on next login, which needs a password-authenticated
   `ReissueRecoveryKey`.
   - **Pro:** the owner provably holds the key.
   - **Con:** two more methods, and password-authenticated reissue lets a
     password holder replace the recovery key.
3. **Provisional enrollment.** `ConsumePairing` consumes the code and creates a
   provisional enrollment that expires, for example after 10 minutes, unless
   `ConfirmEnrollment(s recovery_key)` commits it. If delivery fails, the
   provisional state expires back to Unenrolled, and the owner re-enables from
   the console for a new pairing.
   - **Pro:** no enrollment exists without proof the owner holds the key.
   - **Con:** another transient state with its own crash semantics, and a
     failed delivery costs a fresh console pairing.
4. **Password-authenticated recovery-key regeneration at any time.** Keep
   design 1, but add a password-authenticated `RegenerateRecoveryKey` for
   later repair.
   - **Pro:** simple, and repair is possible.
   - **Con:** the password alone can replace the recovery key, so the recovery
     key is no longer independent of the password. That may be acceptable for
     a single-operator appliance.

Relevant to all four: the recovery key is held in memory only between
generation and the reply, and is never logged. The contract says the recovery
key is "shown once at enrollment" and that only its hash is kept. Designs 2 to
4 add a method or state beyond the contract's list and would need review
against it.

## Security properties provable by unit tests
Using an injected clock, an injected random source and a temporary state
directory:
- **State machine:**
  - each transition in the table above, and that no other transition is
    possible;
  - `EnsurePendingPairing` is idempotent and does not rotate an unexpired
    code;
  - it's a no-op when enrolled;
  - it creates a new code after expiry.
- **Pairing:** a code is single-use, is refused after expiry and after the
  failure cap, and `ConsumePairing` succeeds only in Pending pairing.
- **Verification:** `VerifyPassword` never succeeds when Unenrolled, succeeds
  only for the enrolled password, and returns `RateLimited` during backoff
  without evaluating the password.
- **Recovery and reset:**
  - `RecoverPassword` changes only the password hash and the relevant
    counter;
  - `ResetEnrollment` clears credentials and any pending pairing;
  - `GetPendingPairing` and `GetEnrollmentState` never change state.
- **Backoff:** the arithmetic, independent counters per path, and
  persistence through a simulated restart.
- **Formats:**
  - password bounds and rules;
  - pairing-code and recovery-key formats and alphabets, with lengths and
    entropy coming from the injected source;
  - the Argon2id parameters encoded in the stored PHC string and honored on
    verification.
- **Storage:**
  - atomic-write behavior, where simulated failures before rename leave the
    old state intact;
  - an unknown or corrupt state file yields `Unavailable`, not a reset.
- **Secrecy:** no secret (password, code or key) appears in logs or error
  messages; comparisons of codes and keys are constant-time.
- **Signatures:** calls with wrong signatures, including arguments to
  zero-argument methods, are rejected with `InvalidArgs`.

## Runtime properties deferred to 5E
Not provable by unit tests, and not claimed here:
- the installed D-Bus policy admits exactly the caller matrix;
- SELinux confinement of `sl_authd_t`, labeling of `/var/lib/sl-authd`, and
  the `send_msg` rules restricting Platform-only methods to `sl_platformd_t`;
- systemd `StateDirectory` ownership, mode and hardening under the real unit;
- restart behavior of the real service, including backoff persistence and
  pending-pairing behavior;
- the boot-time reset worker's ordering relative to sl-authd;
- journal logging of authentication events with no secrets;
- behavior under memory pressure and denial-of-service, which is also listed
  for the hardening release.

## Open questions
1. **Pending pairing code at rest.** Keep it in memory only (a restart
   invalidates it and Enable creates a new one), or persist it retrievably in
   the state file?
2. **Recovery-key delivery design.** Choose one of the four candidates in
   Storage.
3. **Recovery key on use.** Rotate it after `RecoverPassword`, which is another
   one-time delivery, this time at the console, or keep it?
4. **Backoff.** Persist across restarts? Keep separate web, console and pairing
   counters? Should `ResetEnrollment` clear them?
5. **`RateLimited` retry-after.** Carry it in the error message text, or as a
   typed value, for example a separate `GetBackoff` or a changed return type?
6. **`GetEnrollmentState` caller sl-sessiond.** This is derived from the
   schema 0.4 definition. Confirm, or have Session1 obtain `enrolled` through
   Platform instead.
7. **`CancelPendingPairing`.** Derived from Disable's contract semantics.
   Confirm it as a separate fixed method.
8. **Boot-time reset ordering.** The contract routes it through a Platform
   early-boot worker calling sl-authd's methods, so sl-authd must run before
   that worker. Confirm the ordering and that sl-authd tolerates early start.
9. **Console UI service identity name** for the bus policy.
10. **Argon2id memory versus the smallest supported machine,** and whether to
    serialize verifications.
