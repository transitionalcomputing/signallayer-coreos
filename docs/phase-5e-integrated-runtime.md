# Phase 5E integrated runtime acceptance

Phase 5D is deferred for the 0.0.3 release. A durable management UI belongs
above the future Management Plane as an unprivileged managed workload, with
Podman as an implementation backend. Building that layer now would introduce
the Management Plane and role lifecycle before their contracts exist. The
bundled, read-only `sl-remoted` web interface remains the transitional 0.0.3
remote UI.

Phase 5E closes 0.0.3 engineering by validating the already implemented
CoreOS services together in one disposable, genuine-KVM boot. It introduces
no new platform capability. Acceptance covers the immutable base, the trusted
local appliance console, authentication and recovery, remote-management
lifecycle, LAN-only read-only HTTPS service, cross-service status agreement,
SELinux confinement, fail-closed behavior, and the absence of Linux-login or
remote-mutation escape paths.

Integrated validation requires the identity-writing workers to bypass dynamic
systemd userdb lookups, permits their fixed OpenSSL invocation to traverse
public certificate directories, and permits PID 1 to inspect only the
dedicated remote-management TLS identity symlink used by the fixed
`sl-remoted.service` start condition.

The historical 0.0.2 A-to-B-to-A lifecycle remains accepted evidence. Phase
5E does not repeat it unless a concrete deployment-lifecycle regression is
found.
