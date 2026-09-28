"""Focused tests for Phase 5E evidence interpretation."""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("boot_qcow2_phase5e", HERE / "boot-qcow2.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def record(output, exit_code=0):
    return {"exit_code": exit_code, "output": output}


def evidence(audit=""):
    return {
        "phase5e_runtime": record(json.dumps({"checks": {}})),
        "phase5e_release": record('VERSION="0.0.3"\nPLATFORM_API_VERSION="0.3"\n'),
        "phase5e_console_masks": record(
            "getty@.service=masked\nserial-getty@.service=masked\n"
            "console-getty.service=masked\n", 1),
        "phase5e_console_processes": record(""),
        "phase5e_console_unit": record(""),
        "phase5e_bus_platform": record(""),
        "phase5e_bus_auth": record('<policy user="sl-console"></policy>'),
        "phase5e_remoted_unit": record(""),
        "phase5e_final_units": record(""),
        "phase5e_final_state": record("running"),
        "phase5e_final_selinux": record("Enforcing"),
        "phase5e_audit": record(audit),
    }


class Phase5EEvaluatorTests(unittest.TestCase):
    def test_masked_unit_exit_status_is_expected(self):
        checks = boot.evaluate_phase5e(evidence(), 'VERSION="0.0.3"\n')
        self.assertTrue(checks["phase5e_gettys_masked"])

    def test_new_service_avcs_fail_but_accepted_platform_probes_do_not(self):
        platform = "avc: denied { write } scontext=system_u:system_r:sl_platformd_t:s0"
        checks = boot.evaluate_phase5e(evidence(platform), 'VERSION="0.0.3"\n')
        self.assertTrue(checks["phase5e_no_unexpected_service_avcs"])
        worker = "avc: denied { read } scontext=system_u:system_r:sl_remote_worker_t:s0"
        checks = boot.evaluate_phase5e(evidence(worker), 'VERSION="0.0.3"\n')
        self.assertFalse(checks["phase5e_no_unexpected_service_avcs"])


if __name__ == "__main__":
    unittest.main()
