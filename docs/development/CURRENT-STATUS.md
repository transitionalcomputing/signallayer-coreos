# SignalLayer CoreOS — current engineering handoff

**Snapshot:** 2026-10-23. Verify against the current repository and evidence before acting.
**Governing policy:** [ENGINEERING.md](../../ENGINEERING.md).
**Roadmap:** [roadmap to 0.1.0](../roadmap/roadmap-to-0.1.0.md).
**Current milestone:** **0.0.4 — Podman Foundation**, Candidate C feasibility accepted; production architecture approval pending.

## Done

- **0.0.3** CoreOS Developer Preview published and validated. See [0.0.3 closure](../milestones/0.0.3-closure.md).
- **0.0.4 Phase 0:** architecture investigation and reconciliation performed; the initial persistent immutable image-store approach exposed substitution concerns.
- **Phase 1 Pass 1:** bounded genuine-KVM rootless bootstrap feasibility accepted: 37/37 runtime assertions and 11/11 offline checks. This **does not prove production Podman integration**. See [Pass 1 findings](0.0.4-phase1-pass1.md).
- **Candidate C feasibility:** disposable Fedora 44 rootless `podman run --rootfs`
  passed 28/28 assertions under genuine KVM. The root-owned read-only rootfs,
  fixed rootless service, negative missing-rootfs case and native recovery were
  measured without changing the CoreOS image. See
  [Candidate C findings](0.0.4-phase1-pass2-candidate-c.md). Production
  packaging, reset/oracle behavior, dedicated SELinux policy, networking and
  A-to-B-to-A lifecycle remain unproven.
- **Build safeguards:** GitHub PR #34 merged into main, commit `d1c5368e7aedc8e5cb0fbeaf53f865050e594ce9`. This improved release/inventory checks; it did not implement 0.0.4 runtime.

## Current design direction — not runtime proof

- Product owner approved decisions D1–D7 for the 0.0.4 architecture direction.
- **Candidate C**: prefer deployment-owned immutable rootfs via rootless `podman run --rootfs`; **Candidate B**: immutable OCI store/disposable writable graph, comparison only.
- Trusted teardown/relaunch, no unauthorized executable persistence across trusted reset, independent native recovery, and application-data separation are required outcomes.
- General OCI image lifecycle and workload orchestration are **0.0.5 or later**, not 0.0.4.
- The current `main` contract at `docs/contracts/0.0.4-podman-runtime.md` predates the proposed Pass 2 reconciliation. Revised drafts and outside reviews **have not been adopted into main**. Latest independent review found four remaining textual contract corrections: name/constrain the runtime systemd unit; separate permanent spawn prohibitions from transaction inhibit; define verifier dependency activation; remove user-manager assumptions from cgroups.

## Not done / unproven

- Production Candidate C packaging and content-verification oracle: **UNPROVEN**.
- Trusted teardown/reset, permanent spawn exclusion, dedicated production
  SELinux types, approved networking, epoch compatibility and A-to-B-to-A
  lifecycle: **UNPROVEN**.
- 0.0.4 production packages/services and OS integration: **NOT IMPLEMENTED**.
- Full 0.0.4 KVM acceptance, A→B→A lifecycle, artifact and release: **NOT DONE**.

## Next engineering action

Review and approve the bounded
[Phase 1 Pass 3 execution plan](0.0.4-phase1-pass3-plan.md). Before production
implementation, reconcile the runtime contract around Candidate C and approve
the exact package/service inventory, immutable rootfs/oracle format, SELinux
boundary, network policy, reset transaction and compatibility-epoch behavior.
Candidate C's startup result alone does not authorize those changes.

The four open *contract wording* corrections should be handled in a single bounded documentation change, not repeated redesign rounds. No repository document or status note itself authorizes installing runtime packages, changing CoreOS policy, merging, tagging, or publishing.

## How to report checkpoints

- **Done:** measurable behavior with linked evidence.
- **Running:** one currently authorized engineering task.
- **Pending:** next implementation or validation step.
- **Blocked:** only a specific unmet owner authorization, failed security property, or demonstrable technical obstacle.

Update this snapshot when verified facts change. Avoid substituting planning-document revision counts for running software.
