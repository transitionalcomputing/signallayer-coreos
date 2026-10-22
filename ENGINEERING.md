# SignalLayer Engineering Operating Rules

Status: **ADOPTED**, effective 2026-10-21. The adoption prerequisites were
satisfied by merged PR #31 (`00f030d`): the read-only release preflight,
positive and negative tests, and mandatory OCI/qcow2 entry-point gates are in
the accepted history. Previously accepted evidence is not retroactively
invalidated.

## Purpose and accountability

SignalLayer is developed with AI agents and a product owner with extensive infrastructure experience, not a staffed software engineering department. Agents must make omissions visible, limit irreversible changes, and provide independently checkable evidence. AI review is not a security guarantee. The product owner decides product priorities and authorizes materially consequential changes; agents are responsible for surfacing the consequences in plain language.

Priority: security and CoreOS architectural invariants first; mandatory escalation second; explicit task requirements third; existing contracts and release procedures fourth. A task prompt never authorizes an item requiring escalation. Resolve contradictions openly before implementation.

## CoreOS architectural invariants

**SignalLayer CoreOS: Purposefully Boring. Exceptionally Reliable.**

**When everything else fails, CoreOS stands.**

**CoreOS provides the capabilities. SignalLayer Roles consume them.**

- CoreOS owns only the minimal trusted platform: boot, security boundaries, hardware/platform interfaces, update and rollback, lifecycle primitives, and an independent recovery path.
- CloudOS, ServerOS, JumpOS and future roles consume defined CoreOS capabilities. Role-specific applications, interfaces, and business logic do not become CoreOS responsibilities merely because CoreOS can host them.
- Failure, compromise, crash or removal of a role must not, by design, disable CoreOS recovery, silently weaken its security boundaries, or make its essential lifecycle management dependent on that role.
- A component belongs in CoreOS only when (a) boot, security, update, rollback or independent recovery require it with all roles absent, or (b) it is a product-neutral capability behind a stable, versioned contract whose failure cannot disable (a). Otherwise it belongs in a role (formerly called a flavor; see `docs/architecture-direction.md`).
- Maintain a reviewed inventory of runtime packages, systemd units, D-Bus services, sysusers entries and Cargo workspace components. Additions and removals must be explained, detected by automated inventory comparison and explicitly approved. Treat the existing bundled remote web UI as transitional architecture, not a precedent for adding more role-specific UI to CoreOS.
- Required recovery checks for relevant payload changes: existing update A→B→rollback lifecycle and local-console recovery with remote management stopped. Add failed-role and Management Plane fault-injection tests when those components exist; until then report these guarantees UNPROVEN. Scope expensive regression suites to the changed risk surface, documenting any evidence-reuse rationale.

## Roles

- Engineering lead (any qualified AI/human role, currently ChatGPT): translate goals into bounded acceptance criteria; identify cross-component dependencies and architecture consequences; challenge scope expansion and determine the next engineering gate from evidence. Cannot substitute confidence for verification.
- Implementer (currently Codex): investigate, implement, test, and report evidence. Do not infer approval to expand scope.
- Independent reviewer (a separate session that did not implement the change, currently Claude when available): inspect requirements and diffs without accepting the implementer's conclusions as facts. Report counterexamples and omitted dependencies; do not implement fixes in the same review.
- Product owner: approves changes in direction, new dependencies/services, security-boundary changes, release publication, and material expenditure.

No agent may approve its own high-impact architecture change merely because its tests pass.

## Work entry: required before changing code

For nontrivial changes capture four lines in the PR/task:
1. Outcome and acceptance evidence (including a negative case where applicable).
2. Out of scope and plausible risks.
3. `Release-Identity: <planned OS version> | none`.
4. `CoreOS-Surface-Change: none | <inventory diff>`.
Additional analysis is proportional to the risk, not a mandatory essay.

For tiny documentation-only fixes, a brief rationale and diff check suffice.

## Mandatory escalation before implementation

STOP and obtain explicit product-owner approval before:
- Adding/removing a runtime package or service in the CoreOS inventory, or changing the base image such that its inventory changes (ordinary digest updates with unchanged inventory are exempt).
- Relaxing/modifying SELinux, credentials, authorization, privileged capabilities, network exposure, immutable-root or update/rollback semantics.
- Changing the role architecture or public-facing compatibility contract.
- Broadening maintenance work into a new subsystem.
- Merging, tagging, replacing release assets, or publishing.
- Any unreviewed CoreOS inventory change, release-identity change, or security boundary change. Independent review by a separate session is mandatory for these changes.

Approval must name the specific proposed change and its tradeoffs; a broad authorization to fix a bug is not authorization for those expansions. Report the reason, smaller alternatives, and likely new failure modes.

## Build and acceptance: fail early, test the right thing

- Run inexpensive static checks and focused unit tests first; expensive image builds begin only after prerequisites are met.
- Release-bound OCI work uses
  `tools/build-release-oci <planned-version> [--tag <image-reference>]`,
  which runs `tools/release-preflight <planned-version>` on the host before
  invoking Podman and passes the same independent intent into the first
  container stage. Release-bound qcow2 work uses
  `image/build/build-qcow2.sh --release-intent <planned-version> ...`; its gate
  runs before creating build output or inspecting images. Direct developer
  builds retain their historical commands but do not constitute release intent.
  A release build without an explicit planned version and these gates is not an
  accepted release candidate.
- The OS release version is `N.N.N` or `N.N.N.N`; expected identity surfaces are the Containerfile OCI version label and embedded release-file VERSION, build ID prefix, qcow2 builder source reference/label check/output names, offline inspector identity expectations and matching `docs/releases/<version>.md`. Cargo workspace/package versions are **independent internal identities**: they must be SemVer-valid and consistent with Cargo.lock, and do not have to equal the OS version. Logs using `CARGO_PKG_VERSION` may therefore intentionally differ.
- Release preflight must execute actual consumer checks where available (e.g., `cargo metadata --locked --offline --no-deps`) and cover malformed versions, absent patterns and mismatches; textual greps of simultaneously edited files alone are insufficient.
- Build an artifact only from an identified commit and record source revision, builder inputs, OCI identity/digest, qcow2 SHA-256 and resulting embedded version/origin.
- Every machine acceptance assertion needs a failing fixture derived from captured real failure evidence, or is marked UNPROVEN. Evaluate after the run finishes over explicit lifecycle boundaries. A command sent is not proof of delivery or response; inspect actual output. Harnesses derive expected OS identity from release inputs, not hardcoded version strings.
- Identify assertions that rely on mocks/simulation versus real KVM or hardware. Do not call a system accepted unless the required real-runtime checks have passed.
- Reuse passing evidence when the image payload and pertinent tests are unchanged; version changes require verification of the newly produced image, not claims copied from an earlier artifact.
- One candidate/build/run at a time for bounded maintenance work. Preserve evidence and stop for product, test-harness or security failures. A transient infrastructure failure may be retried once unchanged with a recorded reason; repeated failure requires review.

## Release gates

A release proposal must distinguish: (a) implementation accepted, (b) artifact identity accepted, (c) publication authorized.

Before publishing a new version:
- Confirm declared OS version across maintained release surfaces and artifact names; independently record the bootc origin as the update-channel reference, which need not equal the OS release version. The origin/channel policy is a product-owner decision, not an assumed versioning invariant.
- Confirm image provenance points to the reviewed source and the exact artifact tested.
- Confirm required bootc/offline inspection, security invariants and focused KVM/user-visible acceptance.
- Confirm prior version tags and release assets remain intact. Never retag or overwrite historical releases without explicit authorization.
- Record GO / NO-GO / UNPROVEN with supporting evidence. No automatic merge, tag or publish from a test pass.
- After publication, reconcile README current version, release-note status, a provenance record and a digest-indexed evidence summary in `docs/evidence/`; verify immutable prior-release assets remain intact.

## Evidence and communication

Each checkpoint states measured result, uncertainty and next bounded action. A compact Done/Running/Pending/Blocked display is recommended but not mandatory. Distinguish confirmed defects from suspected defects, harness defects, and deferred/cosmetic issues. Do not hide uncertainty behind an aggregate test count.

When tests disagree with visual or runtime evidence, acceptance is UNPROVEN until reconciled. Security regressions and normal-operation usability defects block release. Console-specific lifecycle rulings live in the console acceptance contract.

## Prevent repetition

After an avoidable failure, add the *smallest executable regression/preflight check* for that failure class. Checklists alone are insufficient. Prefer reading existing build scripts, contracts and tests rather than introducing a parallel source of truth.

Adoption record: `tools/release-preflight` accepts an independent planned OS
version, requires all expected identity surfaces, protects historical tags and
validates Cargo without forcing Cargo's SemVer to equal the OS version. Its
positive, negative and historical replay tests and mandatory entry-point gates
were merged before this policy became effective. Source-declared CoreOS
inventory monitoring was added as the next independent safeguard; installed-
artifact inventory remains a separate acceptance requirement.

## Change control

Changes to these rules use a standalone PR with rationale and a bounded review. For urgent security fixes, document any exception and provide retrospective evidence. Keep requirements proportional to the risk and do not turn a developer preview into an unfinishable production-certification exercise.
