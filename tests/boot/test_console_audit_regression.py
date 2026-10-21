"""Focused tests for the 0.0.3.1 console/audit evidence evaluator."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("boot_qcow2_console_audit", HERE / "boot-qcow2.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def record(output="", exit_code=0):
    return {"exit_code": exit_code, "output": output}


def fixture():
    units = "\n".join([
        "Id=sl-console@tty1.service", "ActiveState=active", "SubState=running",
        "User=sl-console", "Group=sl-console", "TTYPath=/dev/tty1",
        "StandardInput=tty-force", "StandardOutput=tty", "StandardError=journal",
        "CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges=yes", "",
        "Id=sl-console@ttyS0.service", "ActiveState=active", "SubState=running",
        "User=sl-console", "Group=sl-console", "TTYPath=/dev/ttyS0",
        "StandardInput=tty-force", "StandardOutput=tty", "StandardError=journal",
        "CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges=yes",
    ])
    audit = ('SELINUX_ERR op=setxattr invalid_context="system_u:object_r:'
             'invalid_bootcinstall_testlabel_t:s0"\n'
             'AVC avc: denied  { write } comm="bootc" name="objects" '
             'scontext=system_u:system_r:sl_platformd_t:s0')
    evidence = {
        "complete": record("done"),
        "release": record(
            'NAME="SignalLayerIT CoreOS"\nVERSION="0.0.3.1"\n'
            'PLATFORM_API_VERSION="0.3"\nSOURCE_REVISION="abc123"\n'
            'BUILD_ID="0.0.3.1-abc123-candidate"\n'),
        "bootc_status": record(json.dumps({"status": {"booted": {"image": {
            "image": {"image": "localhost/signallayer-coreos:0.0.3.1"},
            "version": "0.0.3.1",
        }}}})),
        "cmdline": record("console=tty0 console=ttyS0,115200n8 loglevel=5"),
        "kernel_printk": record("5 4 1 7"),
        "selinux_before": record("Enforcing"), "selinux_after": record("Enforcing"),
        "system_state_before": record("running"), "system_state_after": record("running"),
        "failed_units_before": record(), "failed_units_after": record(),
        "persistent_journal": record(),
        "journald_config": record("Storage=persistent\n#ForwardToConsole=no"),
        "auditd_state": record("active"),
        "audit_status": record("enabled 1\npid 731\nrate_limit 0"),
        "audit_events_after_status": record(audit),
        "auditd_log_after_status": record(audit),
        "sentinel_journal": record("SL_KERN_NOTICE_HIDDEN\nSL_KERN_WARNING_VISIBLE\nSL_KERN_ERROR_VISIBLE"),
        "console_units": record(units),
        "console_processes": record(
            "1 sl-console tty1 system_u:system_r:sl_console_t:s0 /usr/bin/sl-console\n"
            "2 sl-console ttyS0 system_u:system_r:sl_console_t:s0 /usr/bin/sl-console"),
        "console_capabilities": record(
            "1 CapEff:\t0000000000000000\n2 CapEff:\t0000000000000000"),
        "mounts": record(json.dumps({"filesystems": [
            {"target": "/", "options": "ro,relatime", "children": [
                {"target": "/sysroot", "options": "ro,relatime"}]}]})),
        "root_write": record("Read-only file system", 1),
        "usr_write": record("Read-only file system", 1),
        "auth_policy": record("authhash  file"),
        "platform_policy": record("platformhash  file"),
    }
    for index in range(1, 6):
        evidence[f"session_status_{index}"] = record("status")
    serial = ("SignalLayer CoreOS\nSL_KERN_WARNING_VISIBLE\nSL_KERN_ERROR_VISIBLE\n"
              "Stopped sl-console@tty1.service\n"
              "Stopped sl-console@ttyS0.service\n")
    return evidence, serial


class ConsoleAuditEvaluatorTests(unittest.TestCase):
    def test_valid_evidence_passes(self):
        evidence, serial = fixture()
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertTrue(checks)
        self.assertTrue(all(checks.values()), checks)

    def test_audit_on_serial_fails_isolation(self):
        evidence, serial = fixture()
        serial = serial.replace("Stopped sl-console@tty1.service",
                                'avc: denied { write } comm="bootc"\n'
                                "Stopped sl-console@tty1.service")
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["audit_not_on_serial"])

    def test_legacy_release_identity_fails(self):
        evidence, serial = fixture()
        evidence["release"] = record(
            'NAME="SignalLayerIT CoreOS"\nVERSION="0.0.3"\n'
            'SOURCE_REVISION="abc123"\nBUILD_ID="0.0.3-abc123-pass5"\n')
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["release_identity"])

    def test_legacy_bootc_origin_fails(self):
        evidence, serial = fixture()
        evidence["bootc_status"] = record(json.dumps({"status": {"booted": {"image": {
            "image": {"image": "localhost/signallayer-coreos:0.0.3"},
            "version": "0.0.3",
        }}}}))
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["bootc_origin_identity"])

    def test_callback_suppression_after_ui_fails_isolation(self):
        evidence, serial = fixture()
        serial = serial.replace("Stopped sl-console@tty1.service",
                                "kauditd_printk_skb: 23 callbacks suppressed\n"
                                "Stopped sl-console@tty1.service")
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["audit_not_on_serial"])

    def test_shutdown_audit_after_console_stop_does_not_fail_isolation(self):
        evidence, serial = fixture()
        serial += "kauditd_printk_skb: 23 callbacks suppressed\n"
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertTrue(checks["console_lifecycle_complete"])
        self.assertTrue(checks["audit_not_on_serial"])

    def test_missing_console_stop_boundary_fails_isolation(self):
        evidence, serial = fixture()
        serial = serial.replace("Stopped sl-console@ttyS0.service\n", "")
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["console_lifecycle_complete"])
        self.assertFalse(checks["audit_not_on_serial"])

    def test_audit_before_ui_does_not_fail_isolation(self):
        evidence, serial = fixture()
        serial = "kauditd_printk_skb: 3 callbacks suppressed\n" + serial
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertTrue(checks["audit_not_on_serial"])

    def test_identical_frame_after_input_is_not_a_response(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("ready", "before", "after")]
            paths[0].write_bytes(b"full menu")
            paths[1].write_bytes(b"fragment")
            paths[2].write_bytes(b"fragment")
            self.assertFalse(boot.graphical_response_observed(*paths))

    def test_distinct_invalid_input_frame_is_a_response(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("ready", "before", "after")]
            paths[0].write_bytes(b"full menu")
            paths[1].write_bytes(b"fragment")
            paths[2].write_bytes(b"unknown selection")
            self.assertTrue(boot.graphical_response_observed(*paths))

    def test_screendump_waits_for_two_matching_frames(self):
        class FakeQmp:
            def __init__(self):
                self.frames = iter((b"partial", b"full", b"full"))
                self.calls = 0

            def command(self, name, arguments):
                self.calls += 1
                Path(arguments["filename"]).write_bytes(next(self.frames))

        with tempfile.TemporaryDirectory() as directory:
            qmp = FakeQmp()
            path = Path(directory) / "frame.ppm"
            result = boot.capture_stable_framebuffer(qmp, path, delay=0)
            self.assertEqual(result, boot.checksum(path))
            self.assertEqual(qmp.calls, 3)
            self.assertEqual(path.read_bytes(), b"full")

    def test_console_evaluation_occurs_after_powerdown(self):
        source = (HERE / "boot-qcow2.py").read_text()
        main = source[source.index("def main()") :]
        self.assertLess(main.index('qmp.command("system_powerdown")'),
                        main.rindex("evaluate_console_audit("))

    def test_missing_persistent_audit_fails(self):
        evidence, serial = fixture()
        evidence["audit_events_after_status"] = record("")
        checks = boot.evaluate_console_audit(evidence, serial, "authhash", "platformhash")
        self.assertFalse(checks["audit_probe_retained"])

    def test_blueprint_has_exact_threshold_and_both_consoles(self):
        blueprint = (HERE.parents[1] / "image/build/qcow2.toml").read_text()
        self.assertIn('append = "console=tty0 console=ttyS0,115200n8 loglevel=5"', blueprint)
        for forbidden in ("quiet", "audit=0", "selinux=0"):
            self.assertNotIn(forbidden, blueprint)

    def test_image_includes_and_enables_fedora_auditd(self):
        containerfile = (HERE.parents[1] / "Containerfile").read_text()
        self.assertIn("install --setopt=install_weak_deps=False audit", containerfile)
        self.assertIn("multi-user.target.wants/auditd.service", containerfile)

    def test_cargo_and_os_release_identities_are_intentionally_distinct(self):
        root = HERE.parents[1]
        containerfile = (root / "Containerfile").read_text()
        cargo = (root / "Cargo.toml").read_text()
        lock = (root / "Cargo.lock").read_text()
        builder = (root / "image/build/build-qcow2.sh").read_text()
        inspector = (root / "image/build/inspect-qcow2.sh").read_text()
        readme = (root / "image/build/README.md").read_text()

        # Cargo accepts three-part SemVer; the public OS maintenance release
        # retains its independently versioned four-part identity.
        self.assertIn('version = "0.0.3"', cargo)
        self.assertNotIn('version = "0.0.3.1"', cargo)
        for package in (
            "corectl", "sl-authd", "sl-console", "sl-network-observer",
            "sl-platform-client", "sl-platformd", "sl-protocol",
            "sl-remote-state", "sl-remote-worker", "sl-remoted", "sl-sessiond",
        ):
            self.assertRegex(
                lock, rf'name = "{package}"\nversion = "0\.0\.3"')
        self.assertIn('org.opencontainers.image.version="0.0.3.1"', containerfile)
        self.assertIn("'VERSION=\"0.0.3.1\"'", containerfile)
        self.assertIn(
            'source_ref=${1:-localhost/signallayer-coreos:0.0.3.1}', builder)
        self.assertIn("Source must be CoreOS 0.0.3.1.", builder)
        self.assertIn("signallayer-coreos-0.0.3.1-x86_64.qcow2", builder)
        self.assertIn("localhost/signallayer-coreos:0.0.3.1", inspector)
        self.assertIn("signallayer-coreos-0.0.3.1-x86_64.qcow2", readme)


if __name__ == "__main__":
    unittest.main()
