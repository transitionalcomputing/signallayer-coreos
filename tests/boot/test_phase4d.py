"""Phase 4D harness logic tests; standard-library unittest, no VM.

Run: python3 -m unittest discover -s tests/boot -p 'test_*.py'
"""
import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("boot_qcow2", HERE / "boot-qcow2.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)

MARKER = "printf 'complete\\t0\\tZG9uZQ==\\n' >&3"
BOOT_1 = "11111111-2222-3333-4444-555555555555"
BOOT_2 = "66666666-7777-8888-9999-aaaaaaaaaaaa"


def status(boot_id, api="0.2"):
    return {
        "schema_version": "0.3", "product": "SignalLayerIT CoreOS", "version": "0.0.1",
        "platform_api_version": api, "source_revision": "abc", "build_id": "b",
        "machine": {"machine_id": "0" * 32, "architecture": "x86_64", "boot_id": boot_id},
        "network": {"state": "connected_global", "primary_connection": None},
        "booted": {"deployment_id": "d.0", "image_reference": "localhost/signallayer-coreos:0.0.1",
                   "image_digest": "sha256:" + "a" * 64},
        "retained_rollback": None,
        "update": {"state": "idle", "staged": None, "reboot_required": False, "failure": None},
        "rollback": {"state": "idle", "reboot_required": False, "failure": None},
        "health": {"state": "healthy", "system_state": "running", "failed_units": 0},
    }


def record(output, exit_code=0):
    return {"exit_code": exit_code, "output": output}


def denial(error_name="org.freedesktop.DBus.Error.AccessDenied", uid=987, result="method_error"):
    return json.dumps({
        "request": {"scenario": "start-reboot", "sender": ":1.9", "uid": uid,
                    "destination": "org.signallayer.Platform1", "path": "/org/signallayer/Platform1",
                    "interface": "org.signallayer.Platform1", "member": "StartReboot",
                    "signature": "", "body": []},
        "result": result, "error_name": error_name, "message": "denied"})


def passing_evidence(corectl_exit=0):
    post = status(BOOT_2)
    evidence = {
        "reboot_boot_id": record(BOOT_1 + "\n"),
        "reboot_nonroot_denied": record(denial() + "\n", 1),
        "reboot_pre_status": record(json.dumps(status(BOOT_1))),
        "reboot_marker": record(BOOT_1 + "\n"),
        "post_boot_id": record(BOOT_2 + "\n"),
        "post_previous_boot_id": record(BOOT_1 + "\n"),
        "post_system_state": record("running\n"),
        "post_failed_units": record(""),
        "post_selinux": record("Enforcing\n"),
        "post_platform_status": record(json.dumps(post)),
        "post_session_status": record(json.dumps({"type": "s", "data": [json.dumps(post)]})),
        "post_complete": record("done"),
    }
    if corectl_exit is not None:
        evidence["reboot_corectl"] = record("", corectl_exit)
    return evidence


ONE_RESET = [{"event": "RESET", "data": {"guest": True, "reason": "guest-reset"}}]


class ProbeCompositionTests(unittest.TestCase):
    def compose(self):
        probe = (HERE / "guest-probe.sh").read_text()
        return boot.compose_phase4d_probe(
            probe, MARKER, (HERE / "guest-reboot-probe.sh").read_text(),
            (HERE / "guest-reboot-post-probe.sh").read_text(),
            (HERE / "guest-dbus-boundary.py").read_text())

    def test_phases_are_ordered_around_the_reboot(self):
        probe = self.compose()
        post_branch = probe.index("if [[ -e /var/lib/slprobe-4d/boot1_id ]]; then")
        network = probe.index(boot.PHASE4D_NETWORK_ANCHOR)
        denial_call = probe.index("collect reboot_nonroot_denied")
        marker_write = probe.index("collect reboot_marker")
        complete = probe.index(MARKER)
        reboot = probe.index("collect reboot_corectl /usr/bin/corectl reboot")
        self.assertLess(probe.index("exec 3>"), post_branch)
        self.assertLess(post_branch, network)
        self.assertLess(network, denial_call)
        self.assertLess(denial_call, marker_write)
        self.assertLess(marker_write, complete)
        self.assertLess(complete, reboot)
        self.assertLess(probe.index("trap '' TERM"), reboot)
        self.assertEqual(probe.count("corectl reboot"), 1)

    def test_boundary_source_is_embedded(self):
        probe = self.compose()
        self.assertNotIn(boot.PHASE4D_BOUNDARY_MARKER, probe)
        self.assertIn('if scenario == "start-reboot" and uid.value == 0:', probe)

    def test_post_records_are_prefixed(self):
        post = (HERE / "guest-reboot-post-probe.sh").read_text()
        keys = [line.split()[1] for line in post.splitlines() if line.strip().startswith("collect ")]
        self.assertTrue(keys)
        self.assertTrue(all(key.startswith("post_") for key in keys), keys)

    def test_composed_probe_is_valid_bash(self):
        with tempfile.NamedTemporaryFile("w", suffix=".sh") as script:
            script.write(self.compose())
            script.flush()
            subprocess.run(["bash", "-n", script.name], check=True)

    def test_missing_anchor_is_rejected(self):
        with self.assertRaises(RuntimeError):
            boot.compose_phase4d_probe("no anchors", MARKER, "x", "y", "z")


class RebootEvaluationTests(unittest.TestCase):
    def evaluate(self, evidence, events=ONE_RESET):
        return boot.evaluate_reboot(evidence, events)

    def test_complete_reboot_passes(self):
        checks, details = self.evaluate(passing_evidence())
        self.assertEqual(set(checks), set(boot.PHASE4D_CHECKS))
        self.assertTrue(all(checks.values()), checks)
        self.assertEqual(details["nonroot_start_reboot_error_name"], "org.freedesktop.DBus.Error.AccessDenied")
        self.assertEqual(details["corectl_reboot_exit_code"], 0)

    def test_indeterminate_and_uncaptured_corectl_outcomes_pass_with_boot_2(self):
        for exit_code, expected in ((3, 3), (None, "not captured")):
            checks, details = self.evaluate(passing_evidence(exit_code))
            self.assertTrue(checks["reboot_corectl_outcome_acceptable"], exit_code)
            self.assertEqual(details["corectl_reboot_exit_code"], expected)

    def test_rejected_corectl_outcome_fails(self):
        checks, _ = self.evaluate(passing_evidence(1))
        self.assertFalse(checks["reboot_corectl_outcome_acceptable"])

    def test_acceptable_corectl_outcome_requires_boot_2(self):
        evidence = passing_evidence(None)
        for key in ("post_boot_id", "post_previous_boot_id"):
            del evidence[key]
        checks, _ = self.evaluate(evidence)
        self.assertFalse(checks["reboot_boot_id_changed"])
        self.assertFalse(checks["reboot_corectl_outcome_acceptable"])
        self.assertFalse(checks["management_platform_api_0_2_reboot_accepted"])

    def test_boot_id_must_change_and_link_to_boot_1(self):
        same = passing_evidence()
        same["post_boot_id"] = record(BOOT_1)
        self.assertFalse(self.evaluate(same)[0]["reboot_boot_id_changed"])
        unlinked = passing_evidence()
        unlinked["post_previous_boot_id"] = record(BOOT_2)
        self.assertFalse(self.evaluate(unlinked)[0]["reboot_boot_id_changed"])

    def test_exactly_one_reset_is_required(self):
        for events in ([], ONE_RESET * 2):
            checks, details = self.evaluate(passing_evidence(), events)
            self.assertFalse(checks["reboot_exactly_one_reset"])
            self.assertEqual(details["reset_events"], len(events))

    def test_nonroot_start_reboot_must_be_bus_denied(self):
        for text in (denial("org.signallayer.Platform1.Error.Busy"), denial(uid=0),
                     denial(result="success"), "not json"):
            evidence = passing_evidence()
            evidence["reboot_nonroot_denied"] = record(text, 1)
            self.assertFalse(self.evaluate(evidence)[0]["reboot_nonroot_uid_policy_denied"], text)

    def test_post_boot_state_must_match_pre_boot_state(self):
        for mutate in (lambda s: s["booted"].update(deployment_id="other.0"),
                       lambda s: s["update"].update(state="staged"),
                       lambda s: s["rollback"].update(state="queued"),
                       lambda s: s.update(retained_rollback={"deployment_id": "r.0"})):
            evidence = passing_evidence()
            post = json.loads(evidence["post_platform_status"]["output"])
            mutate(post)
            evidence["post_platform_status"] = record(json.dumps(post))
            evidence["post_session_status"] = record(json.dumps({"type": "s", "data": [json.dumps(post)]}))
            checks, _ = self.evaluate(evidence)
            self.assertFalse(checks["post_booted_deployment_unchanged"] and checks["post_update_rollback_unchanged"])

    def test_platform_and_session_must_agree(self):
        evidence = passing_evidence()
        session = status(BOOT_2)
        session["health"]["failed_units"] = 1
        evidence["post_session_status"] = record(json.dumps({"type": "s", "data": [json.dumps(session)]}))
        self.assertFalse(self.evaluate(evidence)[0]["post_platform_session_agree"])

    def test_api_and_schema_versions_are_enforced(self):
        evidence = passing_evidence()
        pre = status(BOOT_1, api="0.1")
        evidence["reboot_pre_status"] = record(json.dumps(pre))
        self.assertFalse(self.evaluate(evidence)[0]["management_platform_api_0_2_reboot_accepted"])
        evidence = passing_evidence()
        post = status(BOOT_2, api="0.1")
        post["schema_version"] = "0.2"
        evidence["post_platform_status"] = record(json.dumps(post))
        checks, _ = self.evaluate(evidence)
        self.assertFalse(checks["post_platform_api_0_2"])
        self.assertFalse(checks["post_status_schema_0_3"])

    def test_selinux_and_failed_units(self):
        evidence = passing_evidence()
        evidence["post_selinux"] = record("Permissive")
        evidence["post_failed_units"] = record("sl-platformd.service loaded failed failed")
        checks, _ = self.evaluate(evidence)
        self.assertFalse(checks["post_selinux_enforcing"])
        self.assertFalse(checks["post_failed_units_zero"])

    def test_missing_evidence_fails_closed(self):
        checks, _ = self.evaluate({}, [])
        self.assertEqual(set(checks), set(boot.PHASE4D_CHECKS))
        self.assertFalse(any(checks.values()))


def session_evidence():
    envelope = record(json.dumps({"type": "s", "data": [json.dumps(status(BOOT_1))]}))
    return {
        "session_platform_status": record(json.dumps(status(BOOT_1))),
        "session_status": copy.deepcopy(envelope),
        "session_unprivileged_status": copy.deepcopy(envelope),
        "session_platform_stop": record(""),
        "session_unavailable": record("Call failed: Platform status is temporarily unavailable", 1),
        "session_platform_reset_failed": record(""),
        "session_platform_restart": record(""),
        "session_recovered_status": copy.deepcopy(envelope),
    }


class SessionEvidenceTests(unittest.TestCase):
    def test_present_and_valid_recovery_evidence_passes(self):
        self.assertTrue(boot.session_recovery_evidence_valid(session_evidence()))

    def test_absent_evidence_fails(self):
        self.assertFalse(boot.session_recovery_evidence_valid({}))

    def test_each_missing_record_fails(self):
        for key in session_evidence():
            evidence = session_evidence()
            del evidence[key]
            self.assertFalse(boot.session_recovery_evidence_valid(evidence), key)

    def test_failed_recovery_or_unobserved_outage_fails(self):
        for key, value in (("session_platform_restart", record("start-limit-hit", 1)),
                           ("session_recovered_status", record("Call failed: unavailable", 1)),
                           ("session_unavailable", record("{}", 0)),
                           ("session_recovered_status", record("not json"))):
            evidence = session_evidence()
            evidence[key] = value
            self.assertFalse(boot.session_recovery_evidence_valid(evidence), key)


class CorectlOutcomeTests(unittest.TestCase):
    def test_report_states_which_outcome_occurred(self):
        for exit_code, label in ((0, "accepted (exit 0)"), (3, "indeterminate (exit 3)"),
                                 (None, "not captured"), (1, "rejected (exit 1)")):
            _, details = boot.evaluate_reboot(passing_evidence(exit_code), ONE_RESET)
            self.assertEqual(details["corectl_reboot_outcome"], label)

    def test_acceptable_outcomes_require_exactly_one_reset(self):
        for exit_code in (0, 3, None):
            for events in ([], ONE_RESET * 2):
                checks, _ = boot.evaluate_reboot(passing_evidence(exit_code), events)
                self.assertFalse(checks["reboot_corectl_outcome_acceptable"], (exit_code, len(events)))
            checks, _ = boot.evaluate_reboot(passing_evidence(exit_code), ONE_RESET)
            self.assertTrue(checks["reboot_corectl_outcome_acceptable"], exit_code)


class QmpEventTests(unittest.TestCase):
    def test_only_events_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "qmp.jsonl"
            log.write_text("\n".join([
                json.dumps({"QMP": {"version": {}}}), json.dumps({"return": {}, "id": "x"}),
                json.dumps(ONE_RESET[0]), "garbage", json.dumps({"event": "RTC_CHANGE"})]) + "\n")
            names = [event["event"] for event in boot.qmp_events(log)]
            self.assertEqual(names, ["RESET", "RTC_CHANGE"])
        self.assertEqual(boot.qmp_events(Path("/nonexistent/qmp.jsonl")), [])


if __name__ == "__main__":
    unittest.main()
