# SignalLayer Engineering Operating Rules

Status: proposed. Applies to new work after adoption; does not retroactively block already accepted release evidence.

## Purpose and accountability

SignalLayer is developed with AI agents and a product owner with extensive infrastructure experience, not a staffed software engineering department. Agents must make omissions visible, limit irreversible changes, and provide independently checkable evidence. AI review is not a security guarantee. The product owner decides product priorities and authorizes materially consequential changes; agents are responsible for surfacing the consequences in plain language.

Priority: explicit task requirements and security invariants first, then existing repository contracts and release procedures, then this document. In case of conflict, STOP and request a decision rather than silently redefining the goal.

## Roles

- Engineering lead (ChatGPT): translate goals into bounded acceptance criteria; identify cross-component dependencies and architecture consequences; challenge scope expansion and determine the next engineering gate from evidence. Cannot substitute confidence for verification.
- Implementer (Codex): investigate, implement, test, and report evidence. Do not infer approval to expand scope.
- Independent reviewer (Claude, when available): inspect requirements and diffs without accepting the implementer's conclusions as facts. Report counterexamples and omitted dependencies; do not implement fixes in the same review.
- Product owner: approves changes in direction, new dependencies/services, security-boundary changes, release publication, and material expenditure.

No agent may approve its own high-impact architecture change merely because its tests pass.

## Work entry: required before changing code

For a nontrivial task, capture in the PR or task report:
1. User-visible outcome and exact defect/feature being addressed.
2. In scope / explicitly out of scope.
3. Relevant contracts and affected components (including install/boot, update/rollback, SELinux, D-Bus, systemd services, network exposure, build/release pipeline, test harness).
4. Acceptance evidence, including the negative/failure case and which parts require real KVM.
5. Release identity impact: version, release file, OCI labels/references, build ID, bootc origin, names, metadata, checksums, documentation and published assets; state `not applicable` with reason if no release artifact is involved.
6. Known risks and simplest viable implementation, with any added runtime service/dependency clearly identified.

For tiny documentation-only fixes, a brief rationale and diff check suffice.

## Mandatory escalation before implementation

STOP and obtain explicit product-owner approval before:
- Adding/removing a boot-time service, package, daemon or other runtime dependency.
- Relaxing/modifying SELinux, credentials, authorization, privileged capabilities, network exposure, immutable-root or update/rollback semantics.
- Changing the role architecture or public-facing compatibility contract.
- Broadening maintenance work into a new subsystem.
- Merging, tagging, replacing release assets, or publishing.

Approval must name the specific proposed change and its tradeoffs; a broad authorization to fix a bug is not authorization for those expansions. Report the reason, smaller alternatives, and likely new failure modes.

## Build and acceptance: fail early, test the right thing

- Run inexpensive static checks and focused unit tests first; expensive image builds begin only after prerequisites are met.
- For release-bound work, verify the *planned version* consistently across maintained input files and output-name rules **before** build. Never rely on a filename rename as a version fix.
- Build an artifact only from an identified commit and record source revision, builder inputs, OCI identity/digest, qcow2 SHA-256 and resulting embedded version/origin.
- Treat a test harness as its own code requiring tests. A command sent is not evidence that a UI received/responded to it; evaluate full relevant service lifecycle and inspect actual output.
- Identify assertions that rely on mocks/simulation versus real KVM or hardware. Do not call a system accepted unless the required real-runtime checks have passed.
- Reuse passing evidence when the image payload and pertinent tests are unchanged; version changes require verification of the newly produced image, not claims copied from an earlier artifact.
- One candidate/build/run at a time for bounded maintenance work. On failure, preserve evidence, stop, and obtain a revised authorization instead of recursively expanding work.

## Release gates

A release proposal must distinguish: (a) implementation accepted, (b) artifact identity accepted, (c) publication authorized.

Before publishing a new version:
- Confirm release file, OCI version label and reference, build ID, bootc origin, artifact filenames, checksums and release notes agree.
- Confirm image provenance points to the reviewed source and the exact artifact tested.
- Confirm required bootc/offline inspection, security invariants and focused KVM/user-visible acceptance.
- Confirm prior version tags and release assets remain intact. Never retag or overwrite historical releases without explicit authorization.
- Record GO / NO-GO / UNPROVEN with supporting evidence. No automatic merge, tag or publish from a test pass.

## Evidence and communication

Each checkpoint reports **Done / Running / Pending / Blocked**, what was actually measured, and the next bounded action. Distinguish confirmed defects from suspected defects, harness defects, and deferred/cosmetic issues. Do not hide uncertainty behind an aggregate test count.

When tests disagree with visual or runtime evidence, acceptance is UNPROVEN until reconciled. Security regressions and normal-operation usability defects block release; post-termination shutdown output is not automatically a live-console defect.

## Prevent repetition

After an avoidable failure, add the *smallest executable regression/preflight check* for that failure class. Checklists alone are insufficient. Prefer reading existing build scripts, contracts and tests rather than introducing a parallel source of truth.

Initial automation target: a **read-only, pre-build release-identity preflight** derived from existing maintained files; test both matching and mismatched versions, integrate it before expensive builds, and keep v0.0.3 historical references valid. Implement this separately; this document does not itself claim that the preflight exists.

## Change control

Changes to these rules use a standalone PR with rationale and a bounded review. For urgent security fixes, document any exception and provide retrospective evidence. Keep requirements proportional to the risk and do not turn a developer preview into an unfinishable production-certification exercise.
