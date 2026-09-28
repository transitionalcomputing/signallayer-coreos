# sl-remoted remote API (0.0.3)

**Status:** 5C-c draft, **for review at the code-review gate**. Written
before the route code, which implements this document. Derived from the
frozen [remote management contract](remote-management-0.0.3.md), the
[sl-authd interface](authd-interface-0.0.3.md) and the
[Platform API 0.3](platform-api-0.3.md) document; it changes no frozen
decision.

## Service boundary

- sl-remoted serves HTTPS on port **8443** with the machine's TLS identity. It
  is unprivileged (`sl-remoted`), has no capabilities, and holds sessions in
  memory only.
- Its only D-Bus peers are `org.signallayer.Auth1` (VerifyPassword,
  ConsumePairing, ConfirmRecoveryKey) and `org.signallayer.Session1`
  (GetPlatformStatus). It has no Platform1 dependency of any kind.
- The remote machine-management API is **read-only**. There is no route that
  updates, rolls back, reboots or otherwise mutates the machine, and no route
  that changes remote-management lifecycle state. Password recovery is
  console-only.
- Assets are bundled in the binary. No CDN or external resource is loaded.

## TLS

- The identity is resolved once at startup: `tls/current` is read once, and the
  key and certificate come from that same generation directory. Rotation
  happens only while sl-remoted is stopped (Reenroll).
- TLS 1.3 and 1.2 (rustls, ring provider), ALPN `http/1.1`. HTTP/1.1 only.
- If the identity cannot be loaded, sl-remoted exits with an error and never
  listens.

## Network exposure

### Eligibility
- The network view comes only from Session1's status (schema 0.4):
  `network.primary_connection.addresses` (canonical `address/prefix`).
- **Listeners:** one per primary-interface address, excluding loopback,
  unspecified, multicast and link-local addresses. Never a wildcard bind.
- **Sources:** a connection is accepted only if its source address lies within
  one of the primary interface's directly connected prefixes (every
  `address/prefix` of the primary connection, including link-local ones).
  IPv4-mapped IPv6 sources are compared as IPv4.
- **Fail closed:** no listener exists, and no source is eligible, when:
  - Session1 cannot be read, or reports a schema other than 0.4;
  - there is no primary connection;
  - any prefix is `/0`, or any address fails to parse (ambiguous state);
  - the view is stale (see below).
- On-link enforcement is exposure reduction, not authentication. Every
  protected route still requires an authenticated session.

### Change observation and freshness
- **Invalidation trigger:** a kernel rtnetlink socket subscribed to link,
  IPv4/IPv6 address and IPv4/IPv6 route notifications. Message contents are
  not parsed; any notification (or an overrun) is only a trigger.
- **On any trigger:** immediately withdraw eligibility, close all listeners,
  end all open connections, and remove the listening marker. Then wait for
  **500 ms** without further notifications (debounce), and refresh Session1
  once. Only then are new listeners bound and eligibility published.
- **Periodic reconcile:** every **60 s**, Session1 is refreshed. If the
  resulting view differs from the published one, the same withdraw-then-rebind
  sequence runs. If it is identical, nothing is disrupted.
- **Staleness:** a view is stale **120 s** after its last successful
  confirmation. Failed refreshes are retried every **5 s**; if the view becomes
  stale, everything is withdrawn until a refresh succeeds.
- If the rtnetlink socket cannot be created, sl-remoted never listens (fail
  closed): without change notifications, a stale listener could survive for up
  to the reconcile period.
- Session1 refreshes time out after **20 s**.

### Controller concurrency
The controller task is the only consumer of rtnetlink notifications. Every
await it performs is raced against the next notification, so an invalidation
is never queued behind other work:

| Await | If an invalidation arrives during it |
|---|---|
| Idle wait until the next reconcile or retry | Immediate withdrawal, then the debounce. |
| Session1 refresh | The refresh is cancelled (its future is dropped, so its result can never be published); immediate withdrawal, then the debounce and a new refresh. |
| Debounce wait | The debounce restarts; eligibility is already withdrawn. |

When an invalidation and a competing operation are ready in the same poll,
explicit select priority (`biased`, invalidation first) resolves it in favour
of the invalidation.

Withdrawal itself (removing the marker, clearing eligibility and bumping the
generation, which ends open connections, then closing listeners) is
synchronous. Binding listeners and writing the marker are also synchronous,
non-blocking and contain no await: they cannot wait on anything external, and
an invalidation that arrives during them is acted on at the controller's next
poll, immediately after they return.

### Listening marker (`/run/sl-remoted/listening`)
- Present if and only if at least one listener is bound to a currently
  eligible primary-interface address, the view is fresh, and the TLS
  configuration is loaded. It does not depend on any client connection.
- Removed before any withdrawal completes, and absent whenever no eligible
  listener remains. `/run/sl-remoted` is the unit's `RuntimeDirectory=`, so
  systemd removes it when the service stops for any reason.

## Request validation (every route)

- **Host:** must be present and equal, byte for byte, to the endpoint of the
  listener that accepted the connection: `192.0.2.10:8443`, or
  `[2001:db8::10]:8443` in canonical RFC 5952 form. Not merely any eligible
  address: the connection's own local endpoint. Hostnames are unsupported.
  Mismatch: **421** `misdirected`.
- **Origin** (state-changing routes only: pairing, confirmation, login,
  logout): must be present and equal to `https://<that endpoint>`, for
  example `https://192.0.2.10:8443` or `https://[2001:db8::10]:8443`.
  Mismatch or absence: **403** `forbidden_origin`. Read-only GETs do not use
  Origin for authorization; Host validation still applies.
- **Bodies (JSON routes):** `Content-Type` must be exactly `application/json`
  (optionally `; charset=utf-8`), else **415** `unsupported_media_type`. The
  body is at most **4096 bytes**, else **413** `payload_too_large`. It must be
  valid UTF-8 JSON matching the route's object exactly, with no unknown
  fields, else **400** `bad_request`.
- **Credential bounds**, checked before any sl-authd call: passwords at most
  1024 bytes, pairing codes and recovery keys at most 64 bytes, else **400**
  `invalid_argument`. Format and length rules beyond these are sl-authd's.
- **Limits:** at most 64 concurrent connections (others are closed at once);
  a 10 s TLS handshake timeout; a 10 s request-header read timeout.

## Sessions

- **Identifier:** 32 bytes from the kernel CSPRNG (`getrandom`), sent as 64
  lowercase hex characters. It is issued only on a successful login, never
  derived from or upgraded from a client-supplied value.
- **Cookie:** `__Host-sl_session=<id>; Path=/; Secure; HttpOnly;
  SameSite=Strict; Max-Age=28800`.
- **Timeouts:** idle **15 minutes** since the last authenticated request;
  absolute **8 hours** since login. Both use `CLOCK_BOOTTIME`, so time in
  suspend counts. An expired session is removed on its next use.
- **Capacity:** at most 64 sessions; a new login evicts the oldest.
- **Invalid or unknown cookies** are all treated identically: as no session.
- **Logout** removes the server-side session before the response is sent.
- All sessions end when sl-remoted stops (Disable, Reenroll, crash).

## Routes

Every response carries `Cache-Control: no-store`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src
'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action
'none'; frame-ancestors 'none'`. Errors are JSON: `{"error": "<code>"}`.

| Method and path | Session | Origin | Request | Success |
|---|---|---|---|---|
| `GET /` | no | no | — | 200 HTML page |
| `GET /app.js` | no | no | — | 200 JavaScript |
| `GET /app.css` | no | no | — | 200 CSS |
| `POST /api/v1/pair` | no | yes | `{"pairing_code": s, "password": s}` | 200 `{"recovery_key": s}` |
| `POST /api/v1/confirm` | no | yes | `{"recovery_key": s}` | 204 |
| `POST /api/v1/login` | no | yes | `{"password": s}` | 204 and `Set-Cookie` |
| `POST /api/v1/logout` | no | yes | empty body | 204 and an expiring `Set-Cookie` |
| `GET /api/v1/status` | **yes** | no | — | 200 Session1 schema 0.4 JSON, exactly as reported |

- **Pairing** calls `Auth1.ConsumePairing`. The recovery key appears in that
  one response only, and is never stored or logged by sl-remoted.
- **Confirmation** calls `Auth1.ConfirmRecoveryKey`. It needs no session; the
  128-bit key and sl-authd's confirmation backoff protect it.
- **Login** calls `Auth1.VerifyPassword` (sl-authd's web scope). Any session
  cookie sent with the request is ignored; a fresh session is issued.
- **Logout** succeeds whether or not a session was present.
- **Status** requires a session and returns Session1's JSON unchanged. If
  Session1 fails: 503 `unavailable`.
- Unknown paths: **404** `not_found`. Wrong methods: **405**
  `method_not_allowed`. A missing or invalid session on a protected route:
  **401** `unauthenticated`.

### sl-authd error mapping

| Auth1 error | HTTP | `error` |
|---|---|---|
| NotEnrolled | 409 | `not_enrolled` |
| EnrollmentUnconfirmed | 409 | `enrollment_unconfirmed` |
| AlreadyEnrolled | 409 | `already_enrolled` |
| NoPendingPairing | 409 | `no_pending_pairing` |
| InvalidPairingCode | 403 | `invalid_pairing_code` |
| PairingAttemptsExhausted | 403 | `pairing_attempts_exhausted` |
| NoProvisionalEnrollment | 409 | `no_provisional_enrollment` |
| ConfirmationExpired | 409 | `confirmation_expired` |
| InvalidCredential | 401 | `invalid_credential` |
| PasswordRejected | 422 | `password_rejected` |
| RateLimited | 429 | `rate_limited` |
| Busy | 503 | `busy` |
| InvalidArgument | 400 | `invalid_argument` |
| Unavailable, or any bus failure | 503 | `unavailable` |

sl-authd timeouts: 30 s (Argon2id admission can queue).

## Logging

Journal lines name the route, the source address and an outcome code only.
Passwords, pairing codes, recovery keys, session identifiers and cookies are
never logged.

## nftables second layer: deferred

The pinned base's nft(8) documents `fib` results as only `oif`, `oifname`,
`check` and `type`. None reveals whether the route to a source uses a
gateway, and `rt nexthop` describes a packet's own route, not its source's. A
static rule therefore cannot express "on-link source"; doing so would need
per-prefix state kept current by a privileged updater, which is not
permitted. The second layer is deferred to the hardening release, and
application-layer enforcement remains mandatory.
