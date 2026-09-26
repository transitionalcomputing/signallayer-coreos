# SignalLayer CoreOS 0.0.3 remote management contract

**Status:** 5B frozen.

## Charter
0.0.3 = durable build inputs + a trusted local appliance console +
authenticated, LAN-only, read-only remote management + the first real web
console. Remote mutation of the machine is out of scope.

## Non-goals
Remote update, rollback, reboot or any other remote machine mutation;
internet or off-link exposure; multiple users or roles; a shell, root
login or general command execution on the console; operator-supplied
certificates or ACME; generic RPC or file access; fleet management;
firmware/systemd-credential provisioning (later automation path).

## Components and authority
- **sl-platformd:** remains the sole machine-mutation authority. Adds the
  fixed remote-management lifecycle methods below.
- **sl-authd (new):** unprivileged, no capabilities, no network listener,
  its own private persistent state. Owns only authentication state: the
  operator password hash (Argon2id), the recovery-key hash, pending
  pairing state and attempt/backoff state. It exposes only fixed
  authentication operations: credential verification, pairing
  consumption and enrollment establishment, password recovery,
  enrollment reset, and attempt/backoff accounting. It has no
  machine-mutation or authorization-to-act role. Its methods are callable
  only by the components that need them, by bus policy.
- **sl-managementd:** unprivileged, no capabilities. Serves HTTPS and the
  bundled web console. Reads machine state through Session1. Verifies
  credentials through sl-authd and owns web sessions. It owns no
  authoritative machine state and has no mutation authority.
  Authentication, pairing and session state are local to the
  remote-management subsystem, not part of the Platform machine-state
  model.
- **Console UI (new):** runs only on the machine's local console
  (tty/serial), in place of a login prompt. No shell, no command
  execution. Reads through Session1; verifies credentials through
  sl-authd. Its service identity may call exactly
  EnableRemoteManagement, DisableRemoteManagement,
  ReenrollRemoteManagement and GetRemoteManagementEnrollment, and nothing
  else (no update, rollback or reboot). sl-managementd receives none of
  these.

## Trust model
- Access to the machine console (physical, serial or hypervisor console)
  is inside the trusted administrative boundary. For virtual machines,
  hypervisor console permissions are part of SignalLayer's security.
- **Unenrolled:** the console may enable remote management and display
  the pairing information without a credential. This is the unavoidable
  first-owner window.
- **Enrolled:** remote-management lifecycle actions at the console require
  the operator password, with progressive backoff. Password recovery is
  the sole normal exception and requires the recovery key. The boot-time
  reset is the explicit last-resort exception. Without a credential, the
  console shows only machine name, version, console URL and certificate
  fingerprint.
- **Boot-time reset exception:** a party able to access the console and
  invoke the boot-time recovery path can destroy and then reclaim
  remote-management enrollment. This grants control of the
  remote-management subsystem only; it provides no shell and no general
  host mutation authority. Console and boot protection (e.g. a firmware
  or bootloader password, hypervisor console permissions) is the
  operator's responsibility.
- **Stated limitation:** the enrolled-console password requirement is
  enforced by the console UI and sl-authd, not by Platform; Platform
  authorizes the console's service identity by bus policy alone. A
  compromised console UI could therefore invoke its four methods without
  a password, which is bounded to remote-management lifecycle (no machine
  mutation beyond it). Accepted for 0.0.3; see Deferred hardening.

## Platform API 0.3 (local, fixed, zero-argument)
- `EnableRemoteManagement() -> ()`: idempotent. Starts sl-managementd
  through a fixed worker if it isn't running; generates the TLS identity
  if absent. When no operator is enrolled, it ensures an unexpired pending
  pairing exists: if the previous pairing expired, invoking it again
  creates a new pairing without rotating the TLS identity.
- `DisableRemoteManagement() -> ()`: stops sl-managementd; invalidates all
  sessions and any pending pairing; preserves enrollment and TLS
  identity.
- `ReenrollRemoteManagement() -> ()`: resets enrollment in sl-authd,
  invalidates sessions and pairing, rotates the TLS identity, and creates
  a fresh pending pairing.
- `GetRemoteManagementEnrollment() -> (url, fingerprint, pairing_code,
  expires_at)`: typed return; the pairing code and expiry are present
  only while a pairing is pending. It never creates or regenerates a
  credential.
Authorized callers: root and the console UI's service identity only. The
existing methods are unchanged. Callers must not assume these methods
exist below API 0.3. Platform instructs sl-authd through fixed sl-authd
methods; it never manipulates sl-authd's files.

## Enrollment and recovery
1. Remote management is disabled by default.
2. From the console (or as root), the owner enables it. The console shows
   the URL, fingerprint and one-time pairing code.
3. The owner connects over HTTPS, verifies the fingerprint, enters the
   pairing code and sets the operator password. The pairing code is
   invalidated on first use and expires after a short fixed interval.
4. A recovery key is shown once at enrollment. Only its hash is kept.
5. **Password recovery (non-destructive):** at the console, the recovery
   key sets a new password. This changes authentication state only.
6. **Last-resort reset (destructive to enrollment only):** a boot-time
   reset, selected explicitly during boot, wipes remote-management
   enrollment (operator credential, recovery key, TLS identity) through a
   fixed Platform early-boot worker. It does not touch the OS or anything
   else. The owner then enrolls from scratch.
There is no permanent default password.

## Status schema 0.4
Schema 0.3 plus a `remote_management` object with exactly `enabled`,
`listening` and `enrolled` (booleans):
- `enabled`: remote management is administratively enabled.
- `listening`: sl-managementd is currently accepting eligible HTTPS
  connections.
- `enrolled`: sl-authd holds an enrolled operator credential.
Session1 aggregates these facts without owning them. No pairing codes, key
material, session counts or other authentication internals. Authenticated
web sessions receive the status object exactly as reported through
Session1.

## Network exposure
sl-managementd is reachable only on the current primary interface's
addresses, and only from sources within that interface's directly
connected prefixes. It never binds to all addresses. If the primary
interface or its prefixes cannot be determined or are stale, it stops
accepting connections; it never broadens scope. On-link reachability
reduces exposure; it is not authentication. Application-layer enforcement
is required. A second layer is decided after investigating an nftables
fib-based on-link check; no hidden privileged daemon is permitted.

## TLS
A machine-generated key and self-signed certificate, with a
browser-compatible key type. The certificate is long-lived and not
automatically rotated on a short schedule; its trust model is explicit
fingerprint verification, not CA expiry. Re-enrollment and the boot-time
reset replace it.

## API and sessions
HTTPS + JSON, read-only endpoints only. Unauthenticated clients reach
only the login/pairing page and its assets. Sessions use a Secure,
HttpOnly, SameSite=Strict cookie with idle and absolute timeouts, owned by
sl-managementd. Login, pairing and logout require a matching Origin.
Credential attempts are rate-limited in sl-authd. Authentication events
are logged to the journal. The console assets are bundled in the image;
no external CDN.

## Deferred to the dedicated hardening release
Explicitly out of 0.0.3 scope; recorded so it isn't lost:
- Platform-verified authd proofs for console actions (closing the stated
  console-UI limitation).
- Adversarial review of D-Bus authorization and deputy boundaries,
  sl-authd/sl-managementd confinement and SELinux policy.
- Console escape paths; auth, recovery and boot-time-reset abuse cases.
- Argon2id/rate-limit denial-of-service behavior.
- Session fixation, theft and CSRF testing; malformed-input fuzzing.
- TLS key storage and rotation review; on-link enforcement testing.
- Update/rollback privilege boundaries; auditability; supply-chain
  provenance.
That release may change architecture if hardening evidence justifies it.

## Implementation investigations (not open product decisions)
- The second network enforcement layer (nftables fib first).
- sl-authd's exact method set and per-caller bus policy (5C planning).

## 5E validation claims (preview)
Disabled by default; enable, disable and re-enroll only through Platform;
off-link connections refused; unauthenticated access limited to the
login page; pairing code single-use and expiring; no remote mutation
endpoint exists; the enrolled console refuses actions without the
password; recovery-key reset works and changes only authentication
state; re-enrollment rotates the fingerprint and invalidates the old
credential; enrollment retrieval never creates a credential; schema 0.4
exposes no authentication internals; remote status agrees with corectl
and Session1; sl-authd and sl-managementd are unprivileged and confined.
