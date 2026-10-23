# Candidate C evidence verification

Verify the published, sanitized evidence package from the repository root:

```bash
cd docs/evidence/0.0.4-phase1-pass2-candidate-c
sha256sum -c SHA256SUMS
```

Replay the strict evaluator without starting QEMU:

```bash
python3 tests/podman/phase1-pass2-candidate-c/run-qcow2.py \
  --evaluate-report docs/evidence/0.0.4-phase1-pass2-candidate-c/report.json
```

Expected result: 28/28, `all_passed: true`, no failed assertions, and the
explicit UNPROVEN list retained. The substitutions in `REDACTIONS.md` do not
touch evidence records or evaluator predicates.

Run the offline parser, evaluator, and negative controls:

```bash
python3 tests/podman/phase1-pass2-candidate-c/test_harness.py
python3 -m py_compile \
  tests/podman/phase1-pass2-candidate-c/run-qcow2.py \
  tests/podman/phase1-pass2-candidate-c/test_harness.py
bash -n tests/podman/phase1-pass2-candidate-c/guest-probe.sh
```

These checks verify evidence handling; they do not replace the preserved KVM
run.
