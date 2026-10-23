#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

RUNNER_PATH = Path(__file__).with_name("run-qcow2.py")
SPEC = importlib.util.spec_from_file_location("candidate_c_runner", RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RUNNER)
UID = 992
GID = 995


def rec(output="", exit_code=0):
    return {"exit_code": exit_code, "output": output}


def good_report():
    evidence = {key: rec() for key in RUNNER.POSITIVE_KEYS}
    evidence.update({key: rec("expected denial", 1) for key in RUNNER.DENIAL_KEYS})
    evidence.update({
        "complete": rec("candidate-c probe complete"),
        "pinned_origin": rec(json.dumps({"status": {"booted": {"image": {
            "image": {"image": RUNNER.EXPECTED_BASE_ORIGIN},
            "imageDigest": RUNNER.EXPECTED_BASE_MANIFEST,
        }}}})),
        "os_release": rec('NAME="Fedora Linux"\nVERSION_ID=44\n'),
        "pid1": rec("systemd"),
        "podman_version": rec("Version:       5.8.7"),
        "crun_version": rec("crun version 1.28\n+SYSTEMD +SELINUX +CAP +SECCOMP"),
        "selinux": rec("Enforcing"),
        "selinux_after": rec("Enforcing"),
        "fixture_archive_sha": rec(RUNNER.EXPECTED_FIXTURE_ARCHIVE_SHA256 + "  fixture.oci.tar"),
        "passwd_entry": rec(f"sl-management:x:{UID}:{GID}::/var/lib/sl-candidate-c/home:/usr/sbin/nologin"),
        "rootfs_source_stat": rec("uid=0 gid=0 mode=755 type=directory"),
        "rootfs_source_context": rec("system_u:object_r:container_file_t:s0"),
        "rootfs_mount": rec(f"{RUNNER.ROOTFS_PATH} /var/lib/sl-candidate-c/rootfs-source none ro,relatime,bind"),
        "rootfs_binary_sha": rec("0" * 64 + f"  {RUNNER.ROOTFS_PATH}/usr/bin/sl-phase1-fixture"),
        "unit": rec("\n".join([
            "User=sl-management", "Group=sl-management", "Delegate=yes",
            f"ExecStart=/usr/bin/podman run --rootfs --network=none --read-only {RUNNER.ROOTFS_PATH} /usr/bin/sl-phase1-fixture",
        ])),
        "unit_properties": rec(f"Delegate=yes\nControlGroup=/system.slice/{RUNNER.UNIT}"),
        "rootless_info": rec(json.dumps({
            "host": {"security": {"rootless": True}},
            "store": {"graphRoot": "/var/lib/sl-candidate-c/containers/storage"},
        })),
        "container_inspect": rec(json.dumps([{
            "Path": "/usr/bin/sl-phase1-fixture",
            "State": {"Running": True},
            "Config": {"CreateCommand": ["podman", "run", "--rootfs", RUNNER.ROOTFS_PATH, "/usr/bin/sl-phase1-fixture"]},
            "HostConfig": {"NetworkMode": "none", "Privileged": False, "ReadonlyRootfs": True, "CapAdd": [], "Devices": []},
        }])),
        "container_uid_map": rec(f"0 {UID} 1\n1 100000 65536"),
        "container_gid_map": rec(f"0 {GID} 1\n1 100000 65536"),
        "container_status": rec("\n".join([
            "CapInh:\t0000000000000000", "CapPrm:\t0000000000000000",
            "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000",
            "CapAmb:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2",
        ])),
        "container_selinux": rec("system_u:system_r:container_t:s0:c1,c2"),
        "container_cgroup": rec(f"0::/system.slice/{RUNNER.UNIT}"),
        "container_namespaces": rec("\n".join(
            f"{side}_{name}={name}:[{1 if side == 'host' else 2}]"
            for name in ("user", "mnt", "pid", "ipc", "net", "uts", "cgroup")
            for side in ("host", "container")
        )),
        "container_mountinfo": rec("36 25 8:1 /rootfs / ro,nosuid,nodev - ext4 /dev/vdb ro"),
        "process_relationships": rec("100 1 992 995 container_t podman podman run\n101 100 992 995 container_t sl-phase1-fixture /usr/bin/sl-phase1-fixture"),
        "fixture_log": rec("uid=0 euid=0 gid=0 egid=0\nprivileged_write=Read-only file system\nsocket:/run/podman/podman.sock=No such file or directory"),
        "hostile_user_config": rec('runtime="definitely-invalid"'),
        "socket_state": rec("present=0"),
        "service_stop": rec("inactive", 3),
        "missing_rootfs": rec("Error: statfs /run/sl-candidate-c/missing-rootfs: no such file or directory", 125),
        "system_state_after_failure": rec("running"),
        "network_after_failure": rec("active"),
        "native_target_after_failure": rec("active"),
        "failed_units_after_failure": rec(""),
        "service_recovery": rec("active"),
        "container_inspect_recovery": rec(json.dumps([{
            "Path": "/usr/bin/sl-phase1-fixture",
            "State": {"Running": True},
        }])),
        "process_relationships_recovery": rec("201 200 992 995 container_t sl-phase1-fixture /usr/bin/sl-phase1-fixture"),
        "fixture_log_recovery": rec("uid=0 euid=0 gid=0 egid=0\nprivileged_write=Read-only file system"),
        "service_stop_final": rec("inactive", 3),
        "audit": rec("-- No entries --", 1),
    })
    command = [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
        f"if=none,id=fixture,format=raw,readonly=on,file=fixture.ext4",
    ]
    return {
        "qemu_exit_code": 0,
        "command": command,
        "base_qcow2_sha256_before": RUNNER.EXPECTED_BASE_QCOW2_SHA256,
        "base_qcow2_sha256_after": RUNNER.EXPECTED_BASE_QCOW2_SHA256,
        "fixture_disk_sha256_before": RUNNER.EXPECTED_FIXTURE_DISK_SHA256,
        "fixture_disk_sha256_after": RUNNER.EXPECTED_FIXTURE_DISK_SHA256,
        "evidence": evidence,
    }


GOOD_SERIAL = "Candidate C boot\nPowering off\n"


class CandidateCHarnessTests(unittest.TestCase):
    def test_complete_fixture_passes(self):
        result = RUNNER.evaluate(good_report(), GOOD_SERIAL)
        self.assertTrue(result["all_passed"], result)
        self.assertEqual(result["passed"], result["total"])

    def test_every_assertion_has_negative_control(self):
        mutations = {
            "qemu_clean_exit": lambda r: r.update(qemu_exit_code=1),
            "probe_complete": lambda r: r["evidence"]["complete"].update(output="truncated"),
            "evidence_commands_valid": lambda r: r["evidence"]["identity"].update(exit_code=127),
            "genuine_kvm": lambda r: r.update(command=["qemu-system-x86_64", "-machine", "q35,accel=tcg"]),
            "immutable_inputs": lambda r: r.update(base_qcow2_sha256_after="bad"),
            "pinned_base": lambda r: r["evidence"]["pinned_origin"].update(output="{}"),
            "fixture_content_identity": lambda r: r["evidence"]["fixture_archive_sha"].update(output="bad fixture.oci.tar"),
            "target_versions": lambda r: r["evidence"]["podman_version"].update(output="Version: 5.8.6"),
            "selinux_enforcing": lambda r: r["evidence"]["selinux_after"].update(output="Permissive"),
            "rootfs_root_owned": lambda r: r["evidence"]["rootfs_source_stat"].update(output="uid=992 gid=995 mode=755 type=directory"),
            "rootfs_read_only": lambda r: r["evidence"]["rootfs_mount"].update(output=f"{RUNNER.ROOTFS_PATH} source none rw,relatime,bind"),
            "runtime_cannot_write_rootfs": lambda r: r["evidence"]["rootfs_runtime_write"].update(exit_code=0),
            "exact_rootfs_launch": lambda r: r["evidence"]["unit"].update(output="User=sl-management\nExecStart=/usr/bin/podman run image"),
            "rootless_identity_maps": lambda r: r["evidence"]["container_uid_map"].update(output="0 0 1"),
            "process_confinement": lambda r: r["evidence"]["container_cgroup"].update(output="0::/user.slice/other"),
            "private_namespaces": lambda r: r["evidence"]["container_namespaces"].update(output="host_user=user:[1]\ncontainer_user=user:[1]"),
            "no_storage_overlay_root": lambda r: r["evidence"]["container_mountinfo"].update(output="36 25 0:1 / / ro - overlay overlay ro"),
            "container_constraints": lambda r: r["evidence"]["container_status"].update(output="CapEff:\t0000000000000001"),
            "fixture_healthy": lambda r: r["evidence"]["container_inspect"].update(output="[]"),
            "config_injection_ignored": lambda r: r["evidence"]["hostile_user_config"].update(output=""),
            "no_podman_socket": lambda r: r["evidence"]["socket_state"].update(output="present=1"),
            "clean_stop": lambda r: r["evidence"]["service_stop"].update(output="active", exit_code=0),
            "missing_rootfs_rejected": lambda r: r["evidence"]["missing_rootfs"].update(output="started", exit_code=0),
            "native_os_survives_failure": lambda r: r["evidence"]["network_after_failure"].update(output="inactive"),
            "restart_after_failure": lambda r: r["evidence"]["container_inspect_recovery"].update(output="[]"),
            "final_shutdown_clean": lambda r: r["evidence"]["container_exists_final"].update(exit_code=0),
        }
        serial_mutations = {
            "no_related_avc": GOOD_SERIAL + 'avc: denied comm="podman" scontext=container_t\n',
            "complete_lifecycle": "Candidate C boot only\n",
        }
        baseline = RUNNER.evaluate(good_report(), GOOD_SERIAL)
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

    def test_scratch_rootfs_supplies_podman_bind_targets_before_readonly_mount(self):
        probe = Path(__file__).with_name("guest-probe.sh").read_text()
        readonly = probe.index('mount -o remount,bind,ro "$rootfs_mount"')
        for path in ("etc", "run", "proc", "sys", "dev", "tmp", "var", "var/tmp", "home", "root"):
            self.assertLess(probe.index(f'$rootfs_source/{path}'), readonly)
        self.assertLess(probe.index('ln -s /run "$rootfs_source/var/run"'), readonly)
        for path in ("hosts", "hostname", "resolv.conf"):
            self.assertLess(probe.index(f'$rootfs_source/etc/{path}'), readonly)
        self.assertLess(probe.index('ln -s /proc/mounts "$rootfs_source/etc/mtab"'), readonly)
        self.assertIn("stable=$((stable + 1))", probe)
        self.assertIn("podman_user container exists sl-candidate-c-fixture", probe)

    def test_empty_avc_query_is_valid_but_retrieval_failure_is_not(self):
        for output in ("", "-- No entries --"):
            report = good_report()
            report["evidence"]["audit"] = rec(output, 1)
            self.assertTrue(RUNNER.evaluate(report, GOOD_SERIAL)["checks"]["evidence_commands_valid"])
        report = good_report()
        report["evidence"]["audit"] = rec("Failed to open journal", 1)
        self.assertFalse(RUNNER.evaluate(report, GOOD_SERIAL)["checks"]["evidence_commands_valid"])


if __name__ == "__main__":
    unittest.main()
