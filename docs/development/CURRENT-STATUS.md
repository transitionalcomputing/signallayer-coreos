# SignalLayer CoreOS — current engineering handoff

**Snapshot:** 2026-10-23. Verify against the current repository and evidence before acting.
**Governing policy:** [ENGINEERING.md](../../ENGINEERING.md).
**Roadmap:** [roadmap to 0.1.0](../roadmap/roadmap-to-0.1.0.md).
**Current milestone:** **0.0.4 — Podman Foundation**, Phase 1 Pass 2 design/feasibility boundary.

## Done

- **0.0.3** CoreOS Developer Preview published and validated. See [0.0.3 closure](../milestones/0.0.3-closure.md).
- **0.0.4 Phase 0:** architecture investigation and reconciliation performed; the initial persistent immutable image-store approach exposed substitution concerns.
- **Phase 1 Pass 1:** bounded genuine-KVM rootless bootstrap feasibility accepted: 37/37 runtime assertions and 11/11 offline checks. This **does not prove production Podman integration**. See [Pass 1 findings](0.0.4-phase1-pass1.md).
- **Build safeguards:** GitHub PR #34 merged into main, commit `d1c5368e7aedc8e5cb0fbeaf53f865050e594ce9`. This improved release/inventory checks; it did not implement 0.0.4 runtime.

## Current design direction — not runtime proof

- Product owner approved decisions D1–D7 for the 0.0.4 architecture direction.
- **Candidate C**: prefer deployment-owned immutable rootfs via rootless `podman run --rootfs`; **Candidate B**: immutable OCI store/disposable writable graph, comparison only.
- Trusted teardown/relaunch, no unauthorized executable persistence across trusted reset, independent native recovery, and application-data separation are required outcomes.
- General OCI image lifecycle and workload orchestration are **0.0.5 or later**, not 0.0.4.
- The current `main` contract at `docs/contracts/0.0.4-podman-runtime.md` predates the proposed Pass 2 reconciliation. Revised drafts and outside reviews **have not been adopted into main**. Latest independent review found four remaining textual contract corrections: name/constrain the runtime systemd unit; separate permanent spawn prohibitions from transaction inhibit; define verifier dependency activation; remove user-manager assumptions from cgroups.

## Not done / unproven

- **Phase 1 Pass 2 candidate experiments:** not executed.
- Podman Candidate C on actual Fedora 44 rootless `--rootfs`, teardown/activation enforcement, SELinux, subordinate-ID resource attribution, content verification and independent recovery: **UNPROVEN**.
- 0.0.4 production packages/services and OS integration: **NOT IMPLEMENTED**.
- Full 0.0.4 KVM acceptance, A→B→A lifecycle, artifact and release: **NOT DONE**.

## Next engineering action

**Move from design to measured implementation evidence:** after the specific product-owner approval required by `ENGINEERING.md` for the proposed experimental scope and any CoreOS inventory/security changes, run a **bounded, disposable Fedora 44 Candidate C feasibility experiment**. Measure whether rootless Podman can launch from the approved read-only rootfs and whether CoreOS can stop it and remain independently recoverable. Record real positive and negative results. Do not claim full trusted reset or production readiness from mere container startup.

The four open *contract wording* corrections should be handled in a single bounded documentation change, not repeated redesign rounds. No repository document or status note itself authorizes installing runtime packages, changing CoreOS policy, merging, tagging, or publishing.

## How to report checkpoints

- **Done:** measurable behavior with linked evidence.
- **Running:** one currently authorized engineering task.
- **Pending:** next implementation or validation step.
- **Blocked:** only a specific unmet owner authorization, failed security property, or demonstrable technical obstacle.

Update this snapshot when verified facts change. Avoid substituting planning-document revision counts for running software.
