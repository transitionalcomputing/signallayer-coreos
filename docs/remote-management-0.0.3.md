# SignalLayer CoreOS 0.0.3 remote management contract

**Status:** 5B draft. Read-only remote management.

## Charter
0.0.3 adds authenticated, LAN-only, read-only remote management and the
first real web console. Remote mutation of the machine is out of scope.

## Non-goals
Remote update, rollback, reboot or any other remote mutation; internet or
off-link exposure; multiple users or roles; operator-supplied certificates
or ACME; generic RPC, command execution or file access; fleet management.

## Components
- **sl-managementd:** unprivileged, no capabilities. Serves HTTPS and the
  bundled web console. Reads machine state only through the existing read
  path (Session1), consistent with the 0.0.2 rule that management
  consumers sit above sl-sessiond. It owns no authoritative machine state
  and has no mutation authority. Authentication, pairing and web-session
  state are local to the remote management subsystem and are not part of
  the Platform machine-state model.
- **sl-platformd:** remains the sole privileged authority. Gains fixed,
  root-only lifecycle methods for remote management (below).
- **corectl:** local operator interface for enabling, disabling and
  enrolling.

## Platform API 0.3 (local, root-only, fixed)
- `EnableRemoteManagement() -> ()` and `DisableRemoteManagement() -> ()`:
  zero arguments, root-only by bus policy, each starting a fixed worker.
  Enabling generates the TLS identity if absent and a one-time pairing
  credential, then starts sl-managementd. Disabling stops it and
  invalidates any pending pairing credential.
- The existing methods are unchanged. Callers must not assume these
  methods exist below API 0.3.

## First-run flow
1. Remote management is disabled by default.
2. The operator enables it locally (`corectl`, through Platform).
3. The operator retrieves, locally only: the console URL, the TLS
   certificate's SHA-256 fingerprint, and a one-time pairing code.
4. The operator connects over HTTPS, verifies the fingerprint, and enters
   the pairing code to establish the single operator credential.
5. The pairing code is invalidated on first successful use and expires
   after a short fixed interval if unused.
There is no permanent default password.

## Network exposure
sl-managementd is reachable only on the current primary interface's
addresses, and only from sources within that interface's directly
connected prefixes. It never binds to all addresses. If the current
primary interface or its prefixes cannot be determined, or are stale, it
stops accepting connections; it never broadens scope. On-link reachability
reduces exposure; it is not authentication. The enforcement mechanism
(application-layer, plus any second layer) is decided in implementation
planning. No hidden privileged daemon is permitted.

## TLS
A machine-generated key and self-signed certificate, with the SHA-256
fingerprint available locally. Browser-compatible key type. Operator-
supplied certificates are later work.

## API and sessions
- HTTPS + JSON. Read-only endpoints only; no mutation endpoints.
- Unauthenticated clients can reach only the login/pairing page and its
  assets.
- Sessions use a Secure, HttpOnly, SameSite=Strict cookie with idle and
  absolute timeouts. State-changing auth requests (login, pairing,
  logout) require a matching Origin.
- Pairing and login attempts are rate-limited. Authentication events are
  logged to the journal.
- The console's assets are bundled in the image; no external CDN.

## Exposed data
The status schema 0.3 object exactly as reported through Session1, only to
authenticated sessions. Remote-management-specific state is not added to
schema 0.3. Whether it is exposed through a separate object or a future
status schema 0.4 is an open decision below.

## Open decisions (to settle before implementation)
1. **Operator credential after pairing:** a password (stored hashed)
   versus a passkey (WebAuthn), and recovery if it's lost (e.g. local
   re-enrollment). WebAuthn constraints (site-identity rules, IP-address
   origins, and secure-context requirements with a self-signed
   certificate) must be verified before choosing passkeys. A hashed
   password is the likely 0.0.3 answer.
2. **Enrollment retrieval:** how corectl obtains the URL, fingerprint and
   pairing code without reading files directly. Likely a root-only
   Platform method returning them.
3. **Status for remote management:** whether its state (enabled,
   listening, paired) appears in status, which would mean schema 0.4.
4. **Second enforcement layer:** nftables `fib`-based on-link check,
   application-only plus an interface-scoped rule, or a Platform-managed
   firewall worker. Investigate `fib` first.
5. **Certificate lifetime and rotation.**
6. **Disable/re-enable semantics:** whether disabling preserves the
   enrolled operator credential. Disabling always invalidates active
   sessions. Recommended: preserve enrollment across a normal
   disable/re-enable, with a separate local re-enrollment operation for
   credential recovery.

## 5E validation claims (preview)
Disabled by default; enable and disable only through Platform; off-link
connection refused; on-link unauthenticated access limited to login;
pairing code single-use and expiring; no mutation endpoint exists; remote
status agrees with corectl and Session1; sl-managementd unprivileged and
confined; TLS fingerprint matches the locally reported one.
