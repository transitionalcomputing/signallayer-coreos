# Offline evidence verification

From the repository root, verify the preserved files:

```bash
cd docs/evidence/0.0.4-phase1-pass1
sha256sum -c SHA256SUMS
```

Replay the maintained strict evaluator without starting QEMU:

```bash
python3 tests/podman/phase1-pass1/run-qcow2.py \
  --evaluate-report docs/evidence/0.0.4-phase1-pass1/report.json
```

Expected result: `passed: 37`, `total: 37`, `all_passed: true`, no failed
assertions, and the explicit UNPROVEN list retained in `evaluation.json`.

Run the focused offline harness suite:

```bash
python3 -m unittest tests/podman/phase1-pass1/test_harness.py
```

Expected result: 11 tests pass. These tests validate evaluator behavior and
negative controls; they are not substitutes for the preserved KVM evidence.
