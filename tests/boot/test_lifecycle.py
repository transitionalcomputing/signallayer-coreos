"""Lifecycle harness tests: the 3F default is reproduced exactly, and the
release 0.0.2 (4E) mode has the expected checks. Standard-library unittest.

Run: python3 -m unittest discover -s tests/boot -p 'test_*.py'
"""
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
spec = importlib.util.spec_from_file_location("boot_lifecycle", HERE / "boot-lifecycle-qcow2.py")
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)

# Accepted 3F run phase3f-acceptance-20260922-035943 (A and B OCI digests).
A_3F = "sha256:a6a4e17c9f229e53d223f88c8712f3ea90ac5d49d61e0b8384f3f88e2af27b23"
B_3F = "sha256:1b91e4073e46168cfd64dff69d744972577017558402d6de25c7ba929f4471aa"
BOOT_IDS = {
    "seed": "00ed6a3c-3a99-489e-9f14-d7a400ae2bc0",
    "candidate": "c85b9e0c-4f40-48b6-9dbb-4fc0d8cc28f2",
    "after_rollback": "70f018c8-3ac6-4b76-aa14-8b6a8d38394b",
}
NEW_CHECKS = {
    "release_0_0_2_status_all_boots", "candidate_schema_0_3_idle_states",
    "boot_sequence_exactly_three_boots", "activation_reboot_outcome_acceptable",
    "rollback_reboot_outcome_acceptable", "release_0_0_2_identity_all_boots",
    "seed_platform_session_agree",
    "candidate_platform_session_agree", "after_rollback_platform_session_agree",
}


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def record(output, exit_code=0):
    return {"exit_code": exit_code, "output": output}


def probe_bytes():
    return (HERE / "guest-lifecycle-probe.sh").read_bytes()


class DefaultReproduces3FTests(unittest.TestCase):
    def setUp(self):
        self.report = fixture("phase3f-acceptance-report.json")
        self.evidence = fixture("phase3f-acceptance-evidence.json")

    def test_default_probe_is_the_accepted_3f_probe(self):
        self.assertEqual(hashlib.sha256(probe_bytes()).hexdigest(), self.report["probe_sha256"])

    def test_default_command_matches_accepted_3f(self):
        run = pathlib.Path(self.report["output"])
        command = lifecycle.qemu_command(
            self.report["firmware"]["code"], run / "OVMF_VARS.fd",
            run / "complete-lifecycle.qcow2", run, probe_bytes())
        accepted = fixture("phase3f-qemu-command.json")
        self.assertEqual(len(command), len(accepted))
        # Known pre-existing discrepancy: the accepted 3F run's unit credential
        # said "Disposable Phase 3F rollback probe"; the 3F harness committed in
        # 897ca05 says "lifecycle probe". That one Description line is the only
        # difference; every other argument, the probe and the drop-in match.
        unit_index = command.index(lifecycle.credential(
            "systemd.extra-unit.phase3f-probe.service", lifecycle.UNIT))
        self.assertEqual(command[:unit_index] + command[unit_index + 1:],
                         accepted[:unit_index] + accepted[unit_index + 1:])
        accepted_unit = lifecycle.UNIT.replace(
            b"Disposable Phase 3F lifecycle probe", b"Disposable Phase 3F rollback probe")
        self.assertNotEqual(accepted_unit, lifecycle.UNIT)
        self.assertEqual(accepted[unit_index], lifecycle.credential(
            "systemd.extra-unit.phase3f-probe.service", accepted_unit))

    def test_default_checks_reproduce_accepted_3f(self):
        checks = lifecycle.evaluate(self.evidence)
        checks.update(lifecycle.runtime_identity_checks(self.evidence, A_3F, B_3F))
        self.assertEqual(checks, self.report["checks"])
        self.assertEqual(len(checks), 37)

    def test_default_result_semantics(self):
        report = copy.deepcopy(self.report)
        self.assertEqual(lifecycle.overall_result(report), self.report["result"])
        self.assertEqual(lifecycle.overall_result(report), "PASS")
        for key, value in (("qemu_exit", 124), ("source_disk_unchanged", False),
                           ("retained_overlay_exists", False)):
            broken = copy.deepcopy(report)
            broken[key] = value
            self.assertEqual(lifecycle.overall_result(broken), "FAIL", key)
        broken = copy.deepcopy(report)
        broken["checks"]["clean_shutdown"] = False
        self.assertEqual(lifecycle.overall_result(broken), "FAIL")

    def test_accepted_3f_avc_behavior(self):
        self.assertTrue(lifecycle.evaluate(self.evidence)["no_unexpected_relevant_avcs"])
        evidence = copy.deepcopy(self.evidence)
        evidence["avcs_candidate"]["output"] += (
            "\nSep 22 04:02:56.000000 fedora audit[1]: AVC avc:  denied  { read } for  pid=1 "
            'comm="bootc" name="x" scontext=system_u:system_r:install_t:s0 tclass=file permissive=0')
        self.assertFalse(lifecycle.evaluate(evidence)["no_unexpected_relevant_avcs"])


def release_evidence(corectl_exits=(0, 0), sequence=None, agreement=None, schema="0.3", api="0.2",
                     version="0.0.2", reference="localhost/signallayer-coreos:0.0.2"):
    """The accepted 3F evidence, adjusted to what a passing 0.0.2 run records."""
    evidence = copy.deepcopy(fixture("phase3f-acceptance-evidence.json"))
    for suffix in lifecycle.STATUS_SUFFIXES:
        status = json.loads(evidence[f"{suffix}_corectl"]["output"])
        status["schema_version"], status["platform_api_version"] = schema, api
        status["version"], status["booted"]["image_reference"] = version, reference
        evidence[f"{suffix}_corectl"]["output"] = json.dumps(status)
    evidence["activation_reboot_requested"] = record("corectl reboot")
    evidence["rollback_reboot_requested"] = record("corectl reboot")
    for name, exit_code in zip(("activation", "rollback"), corectl_exits):
        if exit_code is not None:
            evidence[f"{name}_reboot_corectl"] = record("", exit_code)
    ids = [BOOT_IDS[key] for key in ("seed", "candidate", "after_rollback")]
    evidence["boot_sequence"] = record("\n".join(sequence if sequence is not None else ids) + "\n")
    for suffix in lifecycle.AGREEMENT_SUFFIXES:
        if agreement == "missing":
            continue
        status = json.loads(evidence[f"{suffix}_corectl"]["output"])
        session = copy.deepcopy(status)
        if agreement == "never":
            session["health"]["failed_units"] = 1
        envelope = json.dumps({"type": "s", "data": [json.dumps(session)]})
        evidence[f"{suffix}_agree_1_platform_a"] = record(json.dumps(status))
        evidence[f"{suffix}_agree_1_session"] = record(envelope)
        evidence[f"{suffix}_agree_1_platform_b"] = record(json.dumps(status))
        evidence[f"{suffix}_agree_attempts"] = record("1\n")
        if agreement != "never":
            evidence[f"{suffix}_agree_converged"] = record("1\n")
    return evidence


class Release002ModeTests(unittest.TestCase):
    def evaluate(self, **kwargs):
        return lifecycle.evaluate_release_0_0_2(release_evidence(**kwargs))

    def test_passing_run(self):
        checks, details = self.evaluate()
        self.assertTrue(all(checks.values()), {k: v for k, v in checks.items() if not v})
        self.assertEqual(details["reboots"], {"activation": "accepted (exit 0)", "rollback": "accepted (exit 0)"})
        self.assertEqual(details["boot_sequence"], [BOOT_IDS[k] for k in ("seed", "candidate", "after_rollback")])
        for suffix in lifecycle.AGREEMENT_SUFFIXES:
            self.assertEqual(details["session_agreement"][suffix]["converged_attempt"], 1)

    def test_check_set_is_3f_with_0_0_2_expectations(self):
        checks, _ = self.evaluate()
        expected = set(fixture("phase3f-acceptance-report.json")["checks"])
        expected -= {"candidate_schema_0_2_idle_states", "runtime_a_matches_source_oci",
                     "runtime_b_matches_registry_oci"}
        self.assertEqual(set(checks), expected | NEW_CHECKS)

    def test_schema_and_api_are_required_at_every_boot(self):
        for schema, api in (("0.2", "0.2"), ("0.3", "0.1")):
            checks, _ = self.evaluate(schema=schema, api=api)
            self.assertFalse(checks["release_0_0_2_status_all_boots"], (schema, api))
        checks, _ = self.evaluate(schema="0.2")
        self.assertFalse(checks["candidate_schema_0_3_idle_states"])

    def test_product_identity_is_0_0_2_at_every_boot(self):
        self.assertTrue(self.evaluate()[0]["release_0_0_2_identity_all_boots"])
        for kwargs in ({"version": "0.0.1"},
                       {"reference": "localhost/signallayer-coreos:0.0.1"}):
            checks, _ = self.evaluate(**kwargs)
            self.assertFalse(checks["release_0_0_2_identity_all_boots"], kwargs)

    def test_registry_targets(self):
        self.assertEqual(lifecycle.DEFAULT_REGISTRY_TARGET,
                         "docker://localhost:5000/signallayer-coreos:0.0.1")
        self.assertEqual(lifecycle.RELEASE_REGISTRY_TARGET,
                         "docker://localhost:5000/signallayer-coreos:0.0.2")

    def test_reboot_outcomes_follow_4d_semantics(self):
        for exits, labels in (((3, None), ("indeterminate (exit 3)", "not captured")),
                              ((None, 0), ("not captured", "accepted (exit 0)"))):
            checks, details = self.evaluate(corectl_exits=exits)
            self.assertTrue(checks["activation_reboot_outcome_acceptable"])
            self.assertTrue(checks["rollback_reboot_outcome_acceptable"])
            self.assertEqual((details["reboots"]["activation"], details["reboots"]["rollback"]), labels)
        checks, details = self.evaluate(corectl_exits=(1, 0))
        self.assertFalse(checks["activation_reboot_outcome_acceptable"])
        self.assertEqual(details["reboots"]["activation"], "rejected (exit 1)")

    def test_outcomes_require_exactly_one_reboot_per_transition(self):
        ids = [BOOT_IDS[k] for k in ("seed", "candidate", "after_rollback")]
        extra = "12345678-1234-1234-1234-123456789abc"
        for sequence in (ids[:2], [ids[0], extra, ids[1], ids[2]], ids + [extra], [ids[0], ids[0], ids[2]]):
            checks, _ = self.evaluate(corectl_exits=(None, None), sequence=sequence)
            self.assertFalse(checks["boot_sequence_exactly_three_boots"], sequence)
            self.assertFalse(checks["activation_reboot_outcome_acceptable"], sequence)
            self.assertFalse(checks["rollback_reboot_outcome_acceptable"], sequence)

    def test_systemctl_reboot_fails_in_0_0_2_mode(self):
        evidence = release_evidence()
        evidence["activation_reboot_requested"] = record("systemctl reboot")
        checks, _ = lifecycle.evaluate_release_0_0_2(evidence)
        self.assertFalse(checks["one_activation_and_one_rollback_reboot"])

    def test_agreement_is_required_at_every_checkpoint(self):
        for agreement in ("never", "missing"):
            checks, _ = self.evaluate(agreement=agreement)
            for suffix in lifecycle.AGREEMENT_SUFFIXES:
                self.assertFalse(checks[f"{suffix}_platform_session_agree"], (agreement, suffix))

    def test_3f_avc_allowlist_is_unchanged(self):
        evidence = release_evidence()
        self.assertTrue(lifecycle.evaluate_release_0_0_2(evidence)[0]["no_unexpected_relevant_avcs"])
        evidence["avcs_seed"]["output"] += (
            "\nSep 22 04:00:58.000000 fedora audit[1]: AVC avc:  denied  { read } for  pid=1 "
            'comm="corectl" scontext=system_u:system_r:sl_platformd_t:s0 tclass=file permissive=0')
        self.assertFalse(lifecycle.evaluate_release_0_0_2(evidence)[0]["no_unexpected_relevant_avcs"])


class Release002ProbeTests(unittest.TestCase):
    def compose(self):
        return lifecycle.compose_release_0_0_2_probe(probe_bytes()).decode()

    def test_reboots_use_corectl_with_term_trap(self):
        probe = self.compose()
        self.assertNotIn("systemctl reboot", probe)
        for name in ("activation", "rollback"):
            requested = probe.index(f"record {name}_reboot_requested 'corectl reboot'")
            trap = probe.index("trap '' TERM", requested)
            reboot = probe.index(f"collect {name}_reboot_corectl corectl reboot")
            self.assertLess(requested, trap)
            self.assertLess(trap, reboot)

    def test_agreement_block_is_4d_code_with_prefix_only(self):
        source = (HERE / "guest-reboot-post-probe.sh").read_text()
        start = source.index(lifecycle.AGREEMENT_START)
        end = source.index(lifecycle.AGREEMENT_END) + len(lifecycle.AGREEMENT_END)
        original = source[start:end]
        for suffix in lifecycle.AGREEMENT_SUFFIXES:
            block = lifecycle.agreement_block(f"{suffix}_agree_")
            self.assertEqual(block.replace(f"{suffix}_agree_", "post_agree_"), original)
            self.assertIn(block, self.compose())

    def test_checkpoints_and_boot_sequence_are_in_order(self):
        probe = self.compose()
        sequence = probe.index('cat /proc/sys/kernel/random/boot_id >> "$state_dir/boot-sequence"')
        seed = probe.index("collect seed_corectl")
        seed_loop = probe.index("seed_agree_${post_attempt}_platform_a")
        activation = probe.index("collect activation_reboot_corectl")
        candidate_loop = probe.index("candidate_agree_${post_attempt}_platform_a")
        rollback = probe.index("collect rollback_reboot_corectl")
        after_loop = probe.index("after_rollback_agree_${post_attempt}_platform_a")
        final = probe.index('collect boot_sequence cat "$state_dir/boot-sequence"')
        shutdown = probe.index("record clean_shutdown_requested 'systemctl poweroff'")
        order = [sequence, seed, seed_loop, activation, candidate_loop, rollback, after_loop, final, shutdown]
        self.assertEqual(order, sorted(order))

    def test_composed_probe_is_valid_bash(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sh") as script:
            script.write(self.compose())
            script.flush()
            subprocess.run(["bash", "-n", script.name], check=True)

    def test_composition_does_not_change_the_default_probe(self):
        before = hashlib.sha256(probe_bytes()).hexdigest()
        self.compose()
        self.assertEqual(hashlib.sha256(probe_bytes()).hexdigest(), before)
        self.assertEqual(before, fixture("phase3f-acceptance-report.json")["probe_sha256"])

    def test_missing_anchor_is_rejected(self):
        with self.assertRaises(RuntimeError):
            lifecycle.compose_release_0_0_2_probe(b"#!/usr/bin/bash\n")


if __name__ == "__main__":
    unittest.main()
