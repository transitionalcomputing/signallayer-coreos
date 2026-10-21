# Phase 1 Pass 1 final acceptance evidence

Status: **ACCEPTED — BOUNDED PHASE 1 PASS 1 FEASIBILITY EXPERIMENT**

This package preserves the final genuine-KVM, two-boot validation of the
rootless Podman bootstrap experiment. The strict evaluator passed all 37
assertions. It establishes feasibility only under the recorded conditions; it
does not accept production Podman integration or authorize Phase 1 Pass 2.

## Directly observed results

- QEMU 10.2.2 used `/dev/kvm` with OVMF from
  `edk2-ovmf-20260812-8.fc44`.
- QEMU exited cleanly after two complete boots. Boot IDs changed from
  `e19541d8-fdbc-4c3b-882d-1cb73fa2ff1d` to
  `f27d7727-3707-4cbd-9bdf-762e05993499`.
- `sl-management-fixture.service` was enabled and active after reboot.
- SELinux was Enforcing on both boots. The structured kernel-journal query was
  valid and returned no related AVC records.
- Container root mapped to host UID 992 and GID 995; remaining IDs used the
  subordinate range beginning at 100000.
- The host container process had empty permitted, effective, bounding and
  ambient capability sets, `NoNewPrivs=1`, seccomp mode 2, and an MCS-isolated
  `container_t` context.
- Same-identity writes to root-owned configuration and unit files and attempts
  to control the system unit were denied.
- On both boots, `/run/sl-management/podman/podman.sock` did not exist as a
  filesystem object, had no `/proc/net/unix` entry, rejected a real Podman API
  connection with `ENOENT`, and was absent from the container-root view.
  Podman's `remoteSocket.exists=true` output was informational and was not
  treated as proof that a socket existed.
- The evaluator ran only after QEMU exited and reported 37/37 PASS.

## Package contents

- `report.json`: exact completed machine report and artifact identities.
- `evaluation.json`: exact strict 37-assertion result.
- `guest-evidence.tsv`: exact raw, structured guest evidence used by replay.
- `serial.log`: complete serial transcript used by replay and AVC review.
- `PROVENANCE.md`: source, host, image and fixture identities.
- `REPRODUCE.md`: offline verification and replay commands.
- `SHA256SUMS`: hashes for every preserved evidence input.

No evidence was redacted or rewritten. The original run remains at
`/home/coreos/sl-phase1-pass1-16e1e6a/run/phase1-pass1-final-93e949e/`
on `slit-coreosdev-01`.

## Explicitly unproven

- collision-, malformed-state-, interruption- and retry-safe identity setup;
- immutable additional image storage;
- dedicated production SELinux domains and data types;
- private rootless networking;
- resource limits and deliberate runtime failure isolation;
- update/rollback compatibility and independent CoreOS recovery;
- production integration and Phase 1 Pass 2.

Podman's observed fallback from systemd cgroup management to `cgroupfs` is an
open engineering decision, not an accepted production default.
