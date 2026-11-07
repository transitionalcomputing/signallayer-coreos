#!/usr/bin/env python3
"""Strict source-model mutation controls. No runtime/service/fixture execution.

Uses only an explicitly selected existing rustc and its generated test binary.
Mutants must compile, pass a positive lifecycle control, and fail the selected
negative through an assertion. Compilation failures/errors/empty tests are NOT
valid detections. Every mutation has one exact textual location in pinned source.
"""
import argparse
import json
import pathlib
import subprocess
import tempfile

MUTATIONS = [
    ("artifact-pin", "|| self.artifact != F5_SHA256", "|| false", "immutable_content_pins"),
    ("transaction-binding", "d.binding != o.binding ||", "false ||", "common_freshness_and_authority_refusals"),
    ("event-coverage", "!o.permanent_spawn_closed || !o.event_coverage_complete", "!o.permanent_spawn_closed", "event_gap_or_coordinator_loss_prevents_publication"),
    ("job-runtime", "|| g.runtime != self.descriptor.expected_job.runtime", "|| false", "independent_expected_job_rejects_guard_selected_ids"),
    ("guard-pidfd", "|| !g.pidfd_matches", "|| false", "guard_only_own_pidfd_confirmed_process"),
    ("exact-persistence", "|| receipt.descriptor != self.descriptor", "|| false", "stale_persistence_receipt_refuses"),
    ("verifier-deadline", "o.now - started > 30", "o.now - started > 60", "verifier_deadline_does_not_bound_teardown"),
    ("result-process", "|| result.checked_at > o.now || result.process != r.process", "|| result.checked_at > o.now", "process_reuse_after_verification_refuses"),
    ("early-release", "self.descriptor.state != State::Operational || !self.inhibited", "!self.inhibited", "inhibit_cannot_release_before_durable_state_ten"),
    ("permanent-exclusion", "!o.permanent_spawn_closed || !o.event_coverage_complete", "!o.event_coverage_complete", "operational_release_allows_long_lived_fresh_observations"),
    ("latched-monitor", "else { self.fail(); }", "else { /* deliberately unlatched mutant */ }", "adverse_operational_observation_latches_failure"),
    ("one-use-verifier-start", "|| self.descriptor.verifier_started.is_some()", "|| false", "verifier_start_is_one_use_and_clock_starts_at_activation"),
    ("ready-before-progress", "if !self.ready { return self.reject(Error::NotReady); }", "if false { return self.reject(Error::NotReady); }", "missing_durability_or_ready_refuses"),
    ("retry-exhaustion", "self.failures.len() >= 5", "self.failures.len() >= 6", "restart_backoff_and_exhaustion_are_bounded"),
]

def run(argv):
    p = subprocess.run(argv, text=True, capture_output=True, timeout=60)
    return {"command": argv, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

def test(binary, name):
    return run([str(binary), "--exact", "tests::" + name, "--test-threads=1"])

def passing(result):
    return result["exit"] == 0 and "1 passed; 0 failed" in result["stdout"]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    source = (root / "management-lifecycle/src/lib.rs").read_text()
    tests = (root / "management-lifecycle/src/tests.rs").read_text()
    result = {"scope": "pure Rust source model; no installed/runtime acceptance", "mutations": []}
    with tempfile.TemporaryDirectory(prefix="sl-p31d-mutations-") as tmp:
        work = pathlib.Path(tmp)
        (work / "tests.rs").write_text(tests)
        (work / "lib.rs").write_text(source)
        compile_args = [str(args.rustc), "--edition=2021", "--test", "-D", "warnings", str(work / "lib.rs"), "-o", str(work / "tests")]
        result["baseline_compile"] = run(compile_args)
        if result["baseline_compile"]["exit"]:
            args.output.write_text(json.dumps(result, indent=2) + "\n")
            return 1
        result["baseline_full"] = run([str(work / "tests"), "--test-threads=1"])
        for name, old, new, target in MUTATIONS:
            entry = {"name": name, "target": target, "detected": False}
            result["mutations"].append(entry)
            if source.count(old) != 1:
                entry["error"] = "selector does not identify exactly one source location"
                continue
            entry["control"] = test(work / "tests", target)
            # Restore baseline after each mutant below, including failed compilation.
            mutant = work / "mutant"
            (work / "lib.rs").write_text(source.replace(old, new, 1))
            entry["compile"] = run(compile_args[:-1] + [str(mutant)])
            if entry["compile"]["exit"] == 0:
                entry["positive"] = test(mutant, "positive_full_lifecycle_requires_durable_publication")
                entry["negative"] = test(mutant, target)
                negative = entry["negative"]
                entry["detected"] = (passing(entry["control"]) and passing(entry["positive"])
                    and negative["exit"] == 101 and "1 failed" in negative["stdout"]
                    and "assertion" in negative["stdout"])
            (work / "lib.rs").write_text(source)
        result["detected"] = sum(x["detected"] for x in result["mutations"])
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"detected": result["detected"], "total": len(MUTATIONS), "baseline_exit": result["baseline_full"]["exit"]}))
    return int(result["detected"] != len(MUTATIONS) or result["baseline_full"]["exit"] != 0)

if __name__ == "__main__":
    raise SystemExit(main())
