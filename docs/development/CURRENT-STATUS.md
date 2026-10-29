# SignalLayer CoreOS — current engineering handoff

**Snapshot:** 2026-10-28. Verify against the current repository and evidence before acting.
**Governing policy:** [ENGINEERING.md](../../ENGINEERING.md).
**Roadmap:** [roadmap to 0.1.0](../roadmap/roadmap-to-0.1.0.md).
**Current milestone:** **0.0.4 — Podman Foundation**, P3-1a merged; P3-1b identity provisioning source implemented for draft review; production runtime integration has not begun.

## Done

- **0.0.3** CoreOS Developer Preview published and validated. See [0.0.3 closure](../milestones/0.0.3-closure.md).
- **0.0.4 Phase 0:** architecture investigation and reconciliation performed; the initial persistent immutable image-store approach exposed substitution concerns.
- **Phase 1 Pass 1:** bounded genuine-KVM rootless bootstrap feasibility accepted: 37/37 runtime assertions and 11/11 offline checks. This **does not prove production Podman integration**. See [Pass 1 findings](0.0.4-phase1-pass1.md).
- **Candidate C feasibility:** disposable Fedora 44 rootless `podman run --rootfs`
  passed 28/28 assertions under genuine KVM. The root-owned read-only rootfs,
  fixed rootless service and negative missing-rootfs case were measured,
  followed by a restart of that same service. This Pass 1 base has no
  `sl-platformd` or appliance console, so independent native recovery was not
  measured. The hostile-config control is inconclusive, the negative controls
  are synthetic, and the pause process was created outside the unit cgroup
  (A4). The CoreOS image was unchanged. See
  [Candidate C findings](0.0.4-phase1-pass2-candidate-c.md). Production
  packaging, reset/oracle behavior, dedicated SELinux policy, networking and
  A-to-B-to-A lifecycle remain unproven.
- **Build safeguards:** GitHub PR #34 merged into main, commit `d1c5368e7aedc8e5cb0fbeaf53f865050e594ce9`. This improved release/inventory checks; it did not implement 0.0.4 runtime.
- **P3-1a:** issue #39 implements planned inventory/build-contract controls and
  positive/negative tests under issue #38's owner authorization. See
  [implementation evidence](0.0.4-phase1-pass3-p3-1a.md). This records proposed
  surfaces without installing or accepting a 0.0.4 runtime.

- **P3-1b:** [issue #41](https://github.com/transitionalcomputing/signallayer-coreos/issues/41)
  authorizes source-only identity provisioning. Library, executable negative
  fixtures and preflight binding are implemented: **53/53** Fedora fixture
  tests and **107/107** tooling tests pass. See [results and remaining gates](0.0.4-phase1-pass3-p3-1b.md).
  No account, service or runtime integration is installed; no image was built.

## Current design direction — not runtime proof

- Product owner approved decisions D1–D7 for the 0.0.4 architecture direction.
- **Candidate C**: prefer deployment-owned immutable rootfs via rootless `podman run --rootfs`; **Candidate B**: immutable OCI store/disposable writable graph, comparison only.
- Trusted teardown/relaunch, no unauthorized executable persistence across trusted reset, independent native recovery, and application-data separation are required outcomes.
- General OCI image lifecycle and workload orchestration are **0.0.5 or later**, not 0.0.4.
- This branch includes locally adopted contract commit `976aaf1`. Issue #38's
  final owner decision approves A/C/D for starting P3-1a and B's development
  direction; it reserves engine security risk acceptance and authorization for
  later runtime gates. The fixed 0.0.4 fixture is offline; 0.0.5 must establish
  authenticated Management Plane communications and 0.0.6 workload networking.
- R1–R10 corrections remain required at their specified downstream gates.
  Runtime-unit directive assertions are deferred to corrected P3-1d; the
  superseded P3-0 sandbox list is not implemented or treated as approved code.

## PR #40 correction checkpoint

- Checkout permissions are normalized to content plus owner-executable state;
  special permission bits, executable drift, content drift and symlinks fail.
- Candidate C narrative corrections preserve all original 28/28 evidence bytes.
  The old Pass 3 plan is explicitly superseded by issue #38 / P3-0 decisions.
- The adopted contract's older private-network passages still need a separate
  approved amendment; they do not prescribe `pasta` for the offline fixture.
  Required Management Plane communications are in 0.0.5 and workload networking
  in 0.0.6. No production networking or full P3-0 implementation is deployed.
- See [correction results and remaining limitations](0.0.4-pr40-review-corrections.md).

## Not done / unproven

- Production Candidate C packaging and content-verification oracle: **UNPROVEN**.
- Trusted teardown/reset, permanent spawn exclusion, dedicated production
  SELinux types, approved networking, epoch compatibility and A-to-B-to-A
  lifecycle: **UNPROVEN**.
- 0.0.4 production packages/services and OS integration: **NOT IMPLEMENTED**.
- Full 0.0.4 KVM acceptance, A→B→A lifecycle, artifact and release: **NOT DONE**.

## Next engineering action

Review the P3-1b draft source PR and its parser/transaction negative controls.
PR #40 is merged at `fea70df`; issue #41 authorized this source-only gate.
Installed integration, P3-1c/1d, builds and acceptance still need their separate
authorization. Actual NSS/SELinux, power-loss and reboot/A→B→A behavior remain
UNPROVEN. Preserve Candidate C's 28/28 evidence; source inventory PASS is not
installed-artifact proof.

## How to report checkpoints

- **Done:** measurable behavior with linked evidence.
- **Running:** one currently authorized engineering task.
- **Pending:** next implementation or validation step.
- **Blocked:** only a specific unmet owner authorization, failed security property, or demonstrable technical obstacle.

Update this snapshot when verified facts change. Avoid substituting planning-document revision counts for running software.
