#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).with_name("run-qcow2.py")
SPEC = importlib.util.spec_from_file_location("phase1_pass1_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)

DIGEST = "sha256:" + "a" * 64
UID = 992
GID = 995


def rec(output="", exit_code=0):
    return {"exit_code": exit_code, "output": output}


def info():
    return {
        "host": {
            "security": {"rootless": True},
            "remoteSocket": {"path": "/run/sl-management/podman/podman.sock", "exists": False},
            "idMappings": {
                "uidmap": [
                    {"container_id": 0, "host_id": UID, "size": 1},
                    {"container_id": 1, "host_id": 100000, "size": 65536},
                ],
                "gidmap": [
                    {"container_id": 0, "host_id": GID, "size": 1},
                    {"container_id": 1, "host_id": 100000, "size": 65536},
                ],
            },
        },
        "store": {
            "configFile": "/etc/containers/storage-sl-management.conf",
            "graphRoot": "/var/lib/sl-management/containers/storage",
            "runRoot": "/run/sl-management/containers",
            "graphDriverName": "overlay",
            "graphStatus": {"Native Overlay Diff": "true"},
        },
    }


def inspect():
    return [{
        "State": {"Running": True, "CgroupPath": "/system.slice/sl-management-fixture.service"},
        "ImageDigest": DIGEST,
        "ImageName": "localhost/sl-phase1-fixture@" + DIGEST,
        "EffectiveCaps": None,
        "BoundingCaps": None,
        "ProcessLabel": "system_u:system_r:container_t:s0:c1,c2",
        "Mounts": [],
        "Config": {"CreateCommand": ["podman", "run", "localhost/sl-phase1-fixture@" + DIGEST]},
        "HostConfig": {
            "Binds": [],
            "NetworkMode": "none",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges"],
            "CapAdd": [],
            "Devices": [],
        },
    }]


def good_report():
    evidence = {key: rec() for key in RUNNER.POSITIVE_KEYS}
    evidence.update({key: rec("denied", 1) for key in RUNNER.DENIAL_KEYS})
    evidence.update({
        "complete": rec("pass1 probe complete"),
        "pid1": rec("systemd"),
        "os_release": rec('NAME="Fedora Linux"\nVERSION_ID=44\n'),
        "kernel": rec("Linux fedora 7.2.7-200.fc44.x86_64"),
        "selinux": rec("Enforcing"),
        "selinux_after": rec("Enforcing"),
        "cgroup_mount": rec("cgroup2 rw,nsdelegate"),
        "podman_version": rec("Version:       5.8.7"),
        "crun_version": rec("crun version 1.28\n+SYSTEMD +SELINUX +CAP +SECCOMP"),
        "passwd_entry": rec(f"sl-management:x:{UID}:{GID}::/var/lib/sl-management:/usr/sbin/nologin"),
        "shadow_entry": rec("sl-management:!:20745::::::"),
        "subuid_after": rec("sl-management:100000:65536"),
        "subgid_after": rec("sl-management:100000:65536"),
        "rootless_info": rec(json.dumps(info())),
        "rootless_info_after": rec(json.dumps(info())),
        "container_inspect": rec(json.dumps(inspect())),
        "container_inspect_after": rec(json.dumps(inspect())),
        "container_uid_map": rec(f"0 {UID} 1\n1 100000 65536"),
        "container_gid_map": rec(f"0 {GID} 1\n1 100000 65536"),
        "container_status": rec("\n".join([
            "CapInh:\t0000000000000000", "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2",
        ])),
        "container_selinux": rec("system_u:system_r:container_t:s0:c1,c2"),
        "container_cgroup": rec("0::/system.slice/sl-management-fixture.service"),
        "unit_properties": rec("Delegate=yes\nControlGroup=/system.slice/sl-management-fixture.service"),
        "fixture_provenance": rec("fixture_manifest=" + DIGEST),
        "boot_id_before": rec("boot-one"),
        "boot_id_after": rec("boot-two"),
        "service_after_reboot": rec("active"),
        "service_enabled": rec("enabled"),
        "login_state": rec("not logged in", 1),
        "user_manager": rec("inactive", 3),
        "system_state": rec("starting", 1),
        "failed_units": rec(""),
        "audit": rec("-- No entries --", 1),
        "rootless_socket_metadata": rec("exists=0"),
        "rootless_socket_metadata_after": rec("exists=0"),
        "rootless_socket_kernel": rec("present=0"),
        "rootless_socket_kernel_after": rec("present=0"),
        "rootless_socket_container_view": rec("exists=0"),
        "rootless_socket_container_view_after": rec("exists=0"),
        "pinned_origin": rec(json.dumps({
            "status": {"booted": {"image": {
                "image": {"image": RUNNER.EXPECTED_BASE_ORIGIN},
                "imageDigest": RUNNER.EXPECTED_BASE_MANIFEST,
            }}},
        })),
        "fixture_archive_sha": rec(RUNNER.EXPECTED_FIXTURE_ARCHIVE_SHA256 + "  fixture.oci.tar"),
        "unit_before_reboot": rec("\n".join([
            "User=sl-management", "Group=sl-management",
            "Environment=XDG_RUNTIME_DIR=/run/sl-management",
            "ExecStart=/usr/bin/podman run --pull=never --network=none --read-only --security-opt=no-new-privileges --cap-drop=all image",
            "Delegate=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
        ])),
        "journal": rec(
            "privileged_write=Read-only file system\n"
            "socket:/run/podman/podman.sock=No such file or directory\n"
            "socket:/run/systemd/private=No such file or directory"
        ),
    })
    evidence["unit_after_reboot"] = copy.deepcopy(evidence["unit_before_reboot"])
    api_error = "cannot connect to /run/sl-management/podman/podman.sock: no such file or directory"
    evidence["rootless_socket_host_api"] = rec(api_error, 1)
    evidence["rootless_socket_host_api_after"] = rec(api_error, 1)
    return {
        "qemu_exit_code": 0,
        "command": [
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-drive", "if=none,id=fixture,format=raw,readonly=on,file=fixture.ext4",
        ],
        "base_qcow2_sha256": RUNNER.EXPECTED_BASE_QCOW2_SHA256,
        "fixture_disk_sha256": RUNNER.EXPECTED_FIXTURE_DISK_SHA256,
        "evidence": evidence,
    }


GOOD_SERIAL = "boot one\nboot two\nreboot: Power down\n"


class HarnessTests(unittest.TestCase):
    def test_complete_fixture_passes(self):
        result = RUNNER.evaluate(good_report(), GOOD_SERIAL)
        self.assertTrue(result["all_passed"], result)
        self.assertEqual(result["passed"], result["total"])

    def test_every_assertion_has_a_negative_control(self):
        mutations = {
            "qemu_clean_exit": lambda r: r.update(qemu_exit_code=1),
            "probe_complete": lambda r: r["evidence"]["complete"].update(output="truncated"),
            "evidence_commands_valid": lambda r: r["evidence"]["systemd"].update(exit_code=127),
            "journal_avc_evidence_valid": lambda r: r["evidence"]["audit"].update(output="journal failed"),
            "genuine_kvm": lambda r: r.update(command=["qemu-system-x86_64", "-machine", "q35,accel=tcg"]),
            "pinned_base": lambda r: r["evidence"]["pinned_origin"].update(output="{}"),
            "pid1_systemd": lambda r: r["evidence"]["pid1"].update(output="bash"),
            "fedora_44": lambda r: r["evidence"]["os_release"].update(output="VERSION_ID=43"),
            "kernel_7_2_7": lambda r: r["evidence"]["kernel"].update(output="Linux 7.2.6"),
            "selinux_enforcing": lambda r: r["evidence"]["selinux_after"].update(output="Permissive"),
            "cgroup_v2": lambda r: r["evidence"]["cgroup_mount"].update(output="tmpfs rw"),
            "podman_5_8_7": lambda r: r["evidence"]["podman_version"].update(output="Version: 5.8.6"),
            "crun_1_28": lambda r: r["evidence"]["crun_version"].update(output="crun version 1.27"),
            "locked_nologin": lambda r: r["evidence"]["shadow_entry"].update(output="sl-management:*:20745::::::"),
            "subuid": lambda r: r["evidence"]["subuid_after"].update(output="sl-management:200000:65536"),
            "subgid": lambda r: r["evidence"]["subgid_after"].update(output="sl-management:200000:65536"),
            "rootless": lambda r: r["evidence"]["rootless_info"].update(output='{"host":{"security":{"rootless":false}}}'),
            "native_overlay": lambda r: r["evidence"]["rootless_info"].update(output='{"store":{"graphDriverName":"vfs"}}'),
            "explicit_store": lambda r: r["evidence"]["rootless_info"].update(output='{"store":{"graphRoot":"/tmp/store"}}'),
            "uid_map": lambda r: r["evidence"]["container_uid_map"].update(output="0 0 1"),
            "gid_map": lambda r: r["evidence"]["container_gid_map"].update(output="0 0 1"),
            "zero_caps_nnp": lambda r: r["evidence"]["container_status"].update(output="CapEff:\t0000000000000001"),
            "container_selinux": lambda r: r["evidence"]["container_selinux"].update(output="unconfined_u:unconfined_r:unconfined_t:s0"),
            "delegated_service_cgroup": lambda r: r["evidence"]["unit_properties"].update(output="Delegate=no"),
            "fixed_image": lambda r: r["evidence"]["fixture_provenance"].update(output="fixture_manifest=sha256:" + "b" * 64),
            "fixture_archive_integrity": lambda r: r["evidence"]["fixture_archive_sha"].update(output="bad  fixture.oci.tar"),
            "fixed_unit_contract": lambda r: r["evidence"]["unit_after_reboot"].update(output="User=root"),
            "container_constraints": lambda r: r["evidence"]["container_inspect"].update(output=json.dumps([{**inspect()[0], "HostConfig": {**inspect()[0]["HostConfig"], "ReadonlyRootfs": False}}])),
            "reboot_restart": lambda r: r["evidence"]["boot_id_after"].update(output="boot-one"),
            "no_login_or_user_manager": lambda r: r["evidence"]["user_manager"].update(exit_code=0, output="active"),
            "rootless_socket_diagnostics_complete": lambda r: r["evidence"]["rootless_socket_metadata"].update(output="exists=1"),
            "host_rootless_socket_absent": lambda r: r["evidence"]["rootless_socket_metadata"].update(output="exists=1\ntype=socket\nmode=600\nuid=992\ngid=995\nselinux=container_runtime_t"),
            "container_rootless_socket_inaccessible": lambda r: r["evidence"]["rootless_socket_container_view"].update(output="exists=1\ntype=socket\nmode=600\nuid=0\ngid=0\nselinux=container_runtime_t"),
            "authority_attacks_denied": lambda r: r["evidence"]["attack_systemctl_stop"].update(exit_code=0, output=""),
            "no_failed_units": lambda r: r["evidence"]["failed_units"].update(output="broken.service failed"),
        }
        baseline = RUNNER.evaluate(good_report(), GOOD_SERIAL)
        serial_mutations = {
            "no_related_avc": GOOD_SERIAL + 'avc: denied comm="podman" scontext=container_t\n',
            "complete_two_boot_lifecycle": "boot one\nboot two\n",
        }
        self.assertEqual(set(mutations) | set(serial_mutations), set(baseline["checks"]))
        for check, mutation in mutations.items():
            with self.subTest(check=check):
                report = copy.deepcopy(good_report())
                mutation(report)
                self.assertFalse(RUNNER.evaluate(report, GOOD_SERIAL)["checks"][check])
        for check, serial in serial_mutations.items():
            with self.subTest(check=check):
                self.assertFalse(RUNNER.evaluate(good_report(), serial)["checks"][check])

    def test_records_reject_missing_malformed_duplicate_and_invalid_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.tsv"
            with self.assertRaisesRegex(ValueError, "missing evidence"):
                RUNNER.records(path)
            cases = (
                "not-tsv\n",
                "key\t0\t***\n",
                "key\t0\t" + base64.b64encode(b"one").decode() + "\nkey\t0\t" + base64.b64encode(b"two").decode() + "\n",
            )
            for content in cases:
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(ValueError):
                        RUNNER.records(path)

    def test_required_command_failure_cannot_pass(self):
        report = good_report()
        report["evidence"]["audit"] = rec("command not found", 127)
        result = RUNNER.evaluate(report, GOOD_SERIAL)
        self.assertFalse(result["all_passed"])
        self.assertIn("evidence_commands_valid", result["failed"])

    def test_empty_avc_query_is_valid_evidence(self):
        for output in ("", "-- No entries --"):
            with self.subTest(output=output):
                report = good_report()
                report["evidence"]["audit"] = rec(output, 1)
                result = RUNNER.evaluate(report, GOOD_SERIAL)
                self.assertTrue(result["checks"]["journal_avc_evidence_valid"])
                self.assertTrue(result["checks"]["evidence_commands_valid"])

    def test_avc_query_failure_and_malformed_results_are_rejected(self):
        cases = ((1, "Failed to open journal"), (0, ""), (0, "{"), (0, '{"MESSAGE":42}'))
        for exit_code, output in cases:
            with self.subTest(exit_code=exit_code, output=output):
                report = good_report()
                report["evidence"]["audit"] = rec(output, exit_code)
                result = RUNNER.evaluate(report, GOOD_SERIAL)
                self.assertFalse(result["checks"]["journal_avc_evidence_valid"])
                self.assertFalse(result["checks"]["evidence_commands_valid"])

        report = good_report()
        del report["evidence"]["audit"]
        result = RUNNER.evaluate(report, GOOD_SERIAL)
        self.assertFalse(result["checks"]["journal_avc_evidence_valid"])
        self.assertFalse(result["checks"]["evidence_commands_valid"])

    def test_structured_related_avc_remains_a_failure(self):
        report = good_report()
        report["evidence"]["audit"] = rec(json.dumps({
            "MESSAGE": 'avc: denied { read } comm="podman" scontext=container_t',
        }))
        result = RUNNER.evaluate(report, GOOD_SERIAL)
        self.assertTrue(result["checks"]["journal_avc_evidence_valid"])
        self.assertFalse(result["checks"]["no_related_avc"])

    def test_socket_api_tool_failure_is_not_connectivity_evidence(self):
        report = good_report()
        report["evidence"]["rootless_socket_host_api"] = rec("podman: command not found", 127)
        result = RUNNER.evaluate(report, GOOD_SERIAL)
        self.assertFalse(result["checks"]["rootless_socket_diagnostics_complete"])
        self.assertFalse(result["checks"]["evidence_commands_valid"])

    def test_missing_or_truncated_json_cannot_pass(self):
        for output in ("", "{", '{"host":'):
            with self.subTest(output=output):
                report = good_report()
                report["evidence"]["rootless_info"]["output"] = output
                result = RUNNER.evaluate(report, GOOD_SERIAL)
                self.assertFalse(result["all_passed"])
                self.assertFalse(result["checks"]["rootless"])

    def test_completed_report_can_be_re_evaluated_without_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text(json.dumps(good_report()))
            (root / "serial.log").write_text(GOOD_SERIAL)
            result = subprocess.run(
                [sys.executable, str(RUNNER_PATH), "--evaluate-report", str(report)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["all_passed"])

    def test_offline_replay_rejects_report_raw_evidence_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text(json.dumps(good_report()))
            (root / "serial.log").write_text(GOOD_SERIAL)
            encoded = base64.b64encode(b"different").decode()
            (root / "guest-evidence.tsv").write_text(f"complete\t0\t{encoded}\n")
            result = subprocess.run(
                [sys.executable, str(RUNNER_PATH), "--evaluate-report", str(report)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("strict raw evidence does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
