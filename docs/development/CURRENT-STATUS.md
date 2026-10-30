# SignalLayer CoreOS — current engineering handoff

**Snapshot:** 2026-10-30. Verify against the current repository and evidence before acting.
**Governing policy:** [ENGINEERING.md](../../ENGINEERING.md).
**Roadmap:** [roadmap to 0.1.0](../roadmap/roadmap-to-0.1.0.md).
**Current milestone:** **0.0.4 — Podman Foundation**, P3-1a/b/c and F5 merged; owner-authorized W1 offline binary/rootfs integration is in source review; production runtime integration has not begun.

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
  fixtures and preflight binding are implemented: **69/69** Fedora fixture
  tests and **107/107** tooling tests pass after the NSS review correction. See [results and remaining gates](0.0.4-phase1-pass3-p3-1b.md).
  No account, service or runtime integration is installed; no image was built.

- **P3-1c / F5:** PR #44 merged at `58312d7e704934e18b274d7eb0c5bca8d3992c71`.
  Under [issue #45](https://github.com/transitionalcomputing/signallayer-coreos/issues/45),
  a separate locked build-only environment resolves the glibc/static mismatch
  without changing the original 543-NEVRA base. Two clean fixture compilations
  are byte-identical; independent ELF checks and a bounded unprivileged smoke
  on the original base pass. Corrected real missing-input controls pass with
  exact failure witnesses. This is a development artifact, not installed CoreOS
  or a runnable production rootfs. See [F5 provenance and limits](0.0.4-f5-static-toolchain.md).

## PR #42 NSS review checkpoint

N1/N2 source corrections check subordinate-ID providers and effective
supplementary membership, accept only the precise local-profile merge syntax,
and return path-specific policy-read errors. PR #42 merged at `33fed192565585bbc1023c201101188087f025dd`; the
source remains uninstalled. N3 measured the exact cached pinned base read-only: it enables
`altfiles` and uses an authselect-owned `nsswitch.conf` symlink. Both remain
refused; **that actual image is not compatible with live provisioning yet**.
Image-supplied `/usr/lib/passwd`/`group` and update/rollback collisions need a
separately reviewed integration, as does any symlink policy path. Recovery,
stale temporaries, UID floor and sysusers/tmpfiles/native integration limitations
are recorded in [the review checkpoint](0.0.4-phase1-pass3-p3-1b.md).

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

F5 merged through PR #46 at `808bb1e0b2337b1393d1f8746c87456f55fd1f94`
after independent GO. W1 is explicitly owner-authorized for source-only offline
packaging, hostile tests, a dedicated branch/push and draft PR. It changes no
installed surface, F5 artifact/toolchain, base inventory or release identity.
W1 native evidence at implementation source `c570cd064e8db9bc14bb5e31bfbad427fdc1e2fb`
now passes: Linux rootfs **120/120**, F5 source tests **106/106**, **22/22**
strict mutations and **2/2** actual reviewed-binary offline roundtrips. All
**111 distinct** tooling checks pass (107 host checks plus four historical
replays with real Git context). Source inventory and structural preflight pass;
Cargo is unavailable here. No implementation or binary rebuild was needed.
See [W1 findings](0.0.4-w1-offline-rootfs.md),
[native evidence](../evidence/0.0.4-w1-native-validation.json), and the
[explicit identity comparison](../evidence/0.0.4-w1-manifest-comparison.json).
Draft PR #48 remains the independent source-review checkpoint; no merge or
production acceptance is inferred. Harness/environment failures are preserved.

The existing F5 native result at `a2cd60c85d2ba79640a427cff780431648ffd8d8`
remains evidence for that build only. W1 synthetic fixtures are not a new native
artifact or installed acceptance. Exact installed ancestry/SELinux labels,
minimal-rootfs execution, immutable runtime mounts, identity compatibility,
trusted reset, native recovery and A→B→A remain UNPROVEN. Do not begin P3-1d.

## How to report checkpoints

- **Done:** measurable behavior with linked evidence.
- **Running:** one currently authorized engineering task.
- **Pending:** next implementation or validation step.
- **Blocked:** only a specific unmet owner authorization, failed security property, or demonstrable technical obstacle.

Update this snapshot when verified facts change. Avoid substituting planning-document revision counts for running software.
