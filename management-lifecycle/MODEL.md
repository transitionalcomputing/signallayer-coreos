# P3-1d source lifecycle model

`src/lib.rs` is a dependency-free Rust source library, compiled directly with
`rustc --edition=2021 --test`. It is not an installed binary, Cargo workspace
component, privileged helper, service or runnable adapter. The existing P3-1b
Python identity source is unchanged and is not invoked.

Outcome: descriptor/state/reset/guard/verifier source logic and positive,
negative and mutation tests, without starting Podman or live systemd services.
Exclusions/risks: no kernel inspection, serialization, fsync, account changes,
unit installation, loaded policy, persistent credentials or production action.
Model tests do not prove runtime authority or isolation.
Release-Identity: none.
CoreOS-Surface-Change: none; source and build-context fingerprints only (existing preflight COPY).

## State and trust

The non-cloneable coordinator owns boot/transaction/reset identities, committed
identity/map observations, exact F5/W1 content identities, deployment digest,
epoch and object identities. At state 1, `ExpectedJob` binds only the fixed
runtime/verifier unit names and a coordinator-generated request token. The token
is not a preassigned systemd Job ID or InvocationID. The trusted adapter must
correlate the actual manager job with that request. At state 8, `bind_runtime`
accepts an independent system-manager activation observation for the exact
transaction/request, recording runtime InvocationID and cgroup. Its descriptor
must be persisted before the pre-start guard compares its own identity. The
guard supplies no verifier ID. `start_verifier` binds the manager-observed
verifier InvocationID only when that fixed dependency actually activates;
manager and runtime-observation claims must match. Distinct source input types
make the provenance requirement explicit but do not prove it. Native manager
correlation, event ordering and guard waiting remain P3-4 integration gates.

Transitions require current observations and simulated durable acknowledgment
of the exact descriptor. READY follows durable state-1 lock acknowledgment,
before spawn inventory or launch wait. Stages 2–7 check exclusion, event
coverage, survivors/holders, quarantine/configuration and content/preconditions.
Configuration records new graph/runroot identities without changing rootfs/data;
new disposable objects cannot alias application data.

The guard consumes authorization once, including on refusal, and requires only
its own pidfd-confirmed process and no populated children. Verifier activation
binds PID/start time and starts its 30-second deadline; prior teardown/launch
does not consume it and repeat activation cannot refresh it. The read-only
verifier constructs a result; only the coordinator advances/publishes trust.
Running is required during measurement; successful completion of the exact
oneshot invocation is required afterward, not permanent verifier liveness.

State 10 must be durably acknowledged before temporary inhibit release.
Permanent exclusion remains required. Adverse operational observations latch
failure; a restored good observation cannot revive trust without reset.
Failure advances the descriptor sequence once and exposes a stop/preserve plan
with `revoke_publication: true`. An exact durable Failed receipt is accepted as
revocation, never as permission to resume. Repeated failure keeps the same
record. Normal transitions reserve the last sequence value for revocation, so
sequence exhaustion cannot leave an operational record without a higher ordered
failure. The adapter must durably record that revocation and execute the plan;
a crash before persistence is still an integration concern. Durable Operational
metadata alone is never live authority, and every restart begins at state 1. Fixture failure may retry with a fresh transaction in the same still-live reset
invocation; actual coordinator restart requires a new reset ID and the previous
reset no longer live. Both paths start at state 1 and retain no token/result.
Data preservation observations apply during reset, not to legitimate operational
application writes; data object identity remains bound throughout. The restart-budget model represents
the proposed five-second backoff and five failures in 300 seconds, not a timer.

## Adapter and evidence limits

Every observation, pidfd assertion and durability receipt is supplied by a
future trusted adapter; current tests construct them in memory. They do not
prove filesystem durability, actual races, crash/power-loss safety, systemd or
SELinux. Cross-process one-use consumption must be atomic and durably bound by
that adapter. In-process ownership is not cross-process replay prevention.
The failure plan must actually be executed by that future adapter. No wire
format/parser or restart-from-disk implementation is installed or accepted.

The fixed F5/W1 constants bind the reviewed offline bundle; no ELF is executed
or rebuilt. Positive label/identity/object booleans are explicitly simulated
later observations, not a conversion of earlier UNPROVEN facts into proof.
A/C/D decisions remain approved; residual engine-risk acceptance is reserved.
W2 identity compatibility stays on HOLD. No interpreted privileged helper is
introduced, and model input cannot make stock-target provisioning compatible.

## Commands

```
rustc --edition=2021 --test -D warnings management-lifecycle/src/lib.rs -o /private/output/lifecycle-tests
/private/output/lifecycle-tests --test-threads=1
python3 -B tests/podman/lifecycle/mutations.py --rustc /absolute/existing/rustc --output /private/output/mutations.json
```

Use a disposable output directory and an existing reviewed compiler. Mutation
controls require compiling mutants, passing original target tests and positive
lifecycle controls, and ordinary negative assertion failures. Errors, skipped
or empty controls, compilation failures and timeouts are not detections.
Root-workspace Cargo metadata is a separate consumer check; this model is not
in that workspace. Future native binaries/provenance need integration review.
