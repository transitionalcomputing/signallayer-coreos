#!/usr/bin/env python3
"""Run the disposable Phase 1 Pass 2 Candidate C feasibility experiment."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

EXPECTED_BASE_ORIGIN = "localhost/sl-phase1-base:pass1"
EXPECTED_BASE_MANIFEST = "sha256:be66d07ce8114567d275a4c92b71a6eb0efb60023f73cfc33727e99355a0b5cb"
EXPECTED_BASE_QCOW2_SHA256 = "60a0eeef6d8f1063f99979cf576bb4a2992a0a1530cba33b2d9b1ef660560cef"
EXPECTED_FIXTURE_DISK_SHA256 = "73d26643bcdb3dc9902d4cd292e19b68d067e16aa984ebecc2dd930193ab2491"
EXPECTED_FIXTURE_ARCHIVE_SHA256 = "b821320317e12471d649ed5a33a068219c45bc7349840a4e978f6f4c8bdd35d1"
ROOTFS_PATH = "/run/sl-candidate-c/rootfs"
UNIT = "sl-candidate-c-fixture.service"

DENIAL_KEYS = {
    "rootfs_runtime_write",
    "missing_rootfs",
    "rootless_socket",
    "container_exists_after_stop",
    "container_exists_final",
    "service_stop",
    "service_stop_final",
}

POSITIVE_KEYS = {
    "pinned_origin", "kernel", "os_release", "pid1", "systemd", "selinux",
    "cgroup_mount", "podman_version", "crun_version", "fixture_archive_sha",
    "fixture_provenance", "identity", "passwd_entry", "subuid", "subgid",
    "rootfs_source_stat", "rootfs_source_context", "rootfs_manifest",
    "rootfs_mount", "rootfs_binary_sha", "hostile_user_config", "unit",
    "unit_properties", "rootless_info", "container_inspect", "container_uid_map",
    "container_gid_map", "container_status", "container_selinux",
    "container_cgroup", "container_namespaces", "container_mountinfo",
    "process_relationships", "fixture_log", "socket_state",
    "network_after_failure", "native_target_after_failure",
    "failed_units_after_failure", "service_recovery", "container_inspect_recovery",
    "process_relationships_recovery", "fixture_log_recovery",
    "selinux_after", "complete",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def records(path: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    if not path.exists():
        raise ValueError(f"missing evidence file: {path}")
    for number, line in enumerate(path.read_text().splitlines(), 1):
        fields = line.split("\t", 2)
        if len(fields) != 3:
            raise ValueError(f"malformed evidence line {number}")
        key = fields[0]
        if not key or key in result:
            raise ValueError(f"empty or duplicate evidence key on line {number}: {key!r}")
        try:
            result[key] = {
                "exit_code": int(fields[1]),
                "output": base64.b64decode(fields[2], validate=True).decode(),
            }
        except (ValueError, UnicodeError) as error:
            raise ValueError(f"invalid evidence record on line {number}: {key!r}") from error
    return result


def _record(evidence, key):
    value = evidence.get(key)
    if not isinstance(value, dict) or not isinstance(value.get("exit_code"), int) or not isinstance(value.get("output"), str):
        return {"exit_code": None, "output": ""}
    return value


def _ok(evidence, key):
    return _record(evidence, key)["exit_code"] == 0


def _text(evidence, key):
    return _record(evidence, key)["output"].strip()


def _json_output(evidence, key):
    if not _ok(evidence, key):
        return None
    output = _record(evidence, key)["output"]
    starts = [pos for pos in (output.find("{"), output.find("[")) if pos >= 0]
    if not starts:
        return None
    start = min(starts)
    try:
        value, end = json.JSONDecoder().raw_decode(output[start:])
    except json.JSONDecodeError:
        return None
    if output[start + end:].strip():
        return None
    return value


def _audit_messages(evidence):
    record = _record(evidence, "audit")
    output = record["output"].strip()
    if record["exit_code"] == 1 and output in {"", "-- No entries --"}:
        return True, []
    if record["exit_code"] != 0 or not output:
        return False, []
    messages = []
    for line in output.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, []
        message = entry.get("MESSAGE") if isinstance(entry, dict) else None
        if not isinstance(message, str):
            return False, []
        messages.append(message)
    return True, messages


def _root_mount(mountinfo: str):
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) > 9 and fields[4] == "/" and "-" in fields:
            separator = fields.index("-")
            return {
                "options": fields[5].split(","),
                "fstype": fields[separator + 1] if separator + 1 < len(fields) else "",
                "source": fields[separator + 2] if separator + 2 < len(fields) else "",
            }
    return {}


def evaluate(report, serial_text):
    evidence = report.get("evidence") if isinstance(report, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    info = _json_output(evidence, "rootless_info") or {}
    inspect_value = _json_output(evidence, "container_inspect")
    inspect_value = inspect_value[0] if isinstance(inspect_value, list) and len(inspect_value) == 1 else {}
    origin = _json_output(evidence, "pinned_origin") or {}
    booted = origin.get("status", {}).get("booted", {}).get("image", {}) if isinstance(origin, dict) else {}
    audit_valid, audit_messages = _audit_messages(evidence)

    passwd_fields = _text(evidence, "passwd_entry").split(":")
    try:
        uid = int(passwd_fields[2])
        gid = int(passwd_fields[3])
    except (IndexError, ValueError):
        uid = gid = -1

    uid_map = _text(evidence, "container_uid_map").split()
    gid_map = _text(evidence, "container_gid_map").split()
    status = _text(evidence, "container_status")
    zero_caps = all(f"{name}:\t0000000000000000" in status for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    unit = _text(evidence, "unit")
    root_mount = _root_mount(_text(evidence, "container_mountinfo"))
    namespaces = _text(evidence, "container_namespaces")
    source_stat = _text(evidence, "rootfs_source_stat")
    source_context = _text(evidence, "rootfs_source_context")
    rootfs_mount = _text(evidence, "rootfs_mount")
    recovery_inspect = _json_output(evidence, "container_inspect_recovery")
    if isinstance(recovery_inspect, list) and len(recovery_inspect) == 1:
        recovery_inspect = recovery_inspect[0]
    else:
        recovery_inspect = {}
    store = info.get("store", {}) if isinstance(info, dict) else {}
    host = info.get("host", {}) if isinstance(info, dict) else {}
    host_config = inspect_value.get("HostConfig", {}) if isinstance(inspect_value, dict) else {}
    create_command = inspect_value.get("Config", {}).get("CreateCommand", []) if isinstance(inspect_value, dict) else []
    related_tokens = ("sl-candidate-c", "sl-management", "container_t", 'comm="podman"', 'comm="crun"', 'comm="conmon"')
    avcs = [line.lower() for line in serial_text.splitlines() if "avc:" in line.lower() and "denied" in line.lower()]
    avcs += [message.lower() for message in audit_messages if "avc:" in message.lower() and "denied" in message.lower()]

    positive_valid = all(_ok(evidence, key) for key in POSITIVE_KEYS)
    denial_valid = all(_record(evidence, key)["exit_code"] not in (None, 0) for key in DENIAL_KEYS)
    system_state = (_record(evidence, "system_state_after_failure")["exit_code"], _text(evidence, "system_state_after_failure"))
    command = report.get("command", []) if isinstance(report, dict) else []

    checks = {
        "qemu_clean_exit": report.get("qemu_exit_code") == 0,
        "probe_complete": _ok(evidence, "complete") and _text(evidence, "complete") == "candidate-c probe complete" and "failure" not in evidence,
        "evidence_commands_valid": positive_valid and denial_valid and audit_valid and system_state in {(0, "running"), (1, "starting")},
        "genuine_kvm": "q35,accel=kvm" in command and "host" in command and report.get("qemu_exit_code") == 0,
        "immutable_inputs": (
            report.get("base_qcow2_sha256_before") == EXPECTED_BASE_QCOW2_SHA256
            and report.get("base_qcow2_sha256_after") == EXPECTED_BASE_QCOW2_SHA256
            and report.get("fixture_disk_sha256_before") == EXPECTED_FIXTURE_DISK_SHA256
            and report.get("fixture_disk_sha256_after") == EXPECTED_FIXTURE_DISK_SHA256
            and any("id=fixture" in item and "readonly=on" in item for item in command)
        ),
        "pinned_base": booted.get("image", {}).get("image") == EXPECTED_BASE_ORIGIN and booted.get("imageDigest") == EXPECTED_BASE_MANIFEST,
        "fixture_content_identity": _text(evidence, "fixture_archive_sha").split()[:1] == [EXPECTED_FIXTURE_ARCHIVE_SHA256],
        "target_versions": (
            'VERSION_ID=44' in _text(evidence, "os_release")
            and "Version:       5.8.7" in _text(evidence, "podman_version")
            and "crun version 1.28" in _text(evidence, "crun_version")
        ),
        "selinux_enforcing": _text(evidence, "selinux") == "Enforcing" and _text(evidence, "selinux_after") == "Enforcing",
        "rootfs_root_owned": "uid=0" in source_stat and "gid=0" in source_stat and "container_file_t" in source_context,
        "rootfs_read_only": ROOTFS_PATH in rootfs_mount and "ro" in rootfs_mount.split()[-1].split(",") and "rw" not in rootfs_mount.split()[-1].split(","),
        "runtime_cannot_write_rootfs": _record(evidence, "rootfs_runtime_write")["exit_code"] not in (None, 0),
        "exact_rootfs_launch": (
            "User=sl-management" in unit
            and "--rootfs" in unit
            and ROOTFS_PATH in unit
            and ":O" not in unit
            and "--privileged" not in unit
            and isinstance(create_command, list)
            and "--rootfs" in create_command
            and ROOTFS_PATH in create_command
        ),
        "rootless_identity_maps": (
            host.get("security", {}).get("rootless") is True
            and uid > 0 and gid > 0
            and uid_map == ["0", str(uid), "1", "1", "100000", "65536"]
            and gid_map == ["0", str(gid), "1", "1", "100000", "65536"]
        ),
        "process_confinement": (
            "Delegate=yes" in _text(evidence, "unit_properties")
            and "/system.slice/" + UNIT in _text(evidence, "container_cgroup")
            and "sl-phase1-fixture" in _text(evidence, "process_relationships")
        ),
        "private_namespaces": all(
            re.search(rf"^host_{name}=(.+)$", namespaces, re.MULTILINE)
            and re.search(rf"^container_{name}=(.+)$", namespaces, re.MULTILINE)
            and re.search(rf"^host_{name}=(.+)$", namespaces, re.MULTILINE).group(1)
            != re.search(rf"^container_{name}=(.+)$", namespaces, re.MULTILINE).group(1)
            for name in ("user", "mnt", "pid", "ipc", "net", "uts")
        ),
        "no_storage_overlay_root": root_mount.get("fstype") not in {"", "overlay"} and "ro" in root_mount.get("options", []),
        "container_constraints": (
            inspect_value.get("State", {}).get("Running") is True
            and host_config.get("NetworkMode") == "none"
            and host_config.get("Privileged") is False
            and host_config.get("ReadonlyRootfs") is True
            and host_config.get("CapAdd") == []
            and host_config.get("Devices") == []
            and zero_caps and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status
            and "container_t:" in _text(evidence, "container_selinux")
        ),
        "fixture_healthy": (
            inspect_value.get("State", {}).get("Running") is True
            and inspect_value.get("Path") == "/usr/bin/sl-phase1-fixture"
            and "/usr/bin/sl-phase1-fixture" in _text(evidence, "process_relationships")
            and re.match(r"^[0-9a-f]{64}\s+" + re.escape(ROOTFS_PATH + "/usr/bin/sl-phase1-fixture") + r"$", _text(evidence, "rootfs_binary_sha")) is not None
        ),
        "config_injection_ignored": "definitely-invalid" in _text(evidence, "hostile_user_config") and inspect_value.get("State", {}).get("Running") is True,
        "no_podman_socket": "present=0" in _text(evidence, "socket_state") and _record(evidence, "rootless_socket")["exit_code"] not in (None, 0),
        "clean_stop": _text(evidence, "service_stop") == "inactive" and _record(evidence, "container_exists_after_stop")["exit_code"] not in (None, 0),
        "missing_rootfs_rejected": (
            _record(evidence, "missing_rootfs")["exit_code"] not in (None, 0)
            and "/run/sl-candidate-c/missing-rootfs" in _text(evidence, "missing_rootfs")
        ),
        "native_os_survives_failure": (
            system_state in {(0, "running"), (1, "starting")}
            and _text(evidence, "network_after_failure") == "active"
            and _text(evidence, "native_target_after_failure") == "active"
            and not _text(evidence, "failed_units_after_failure")
        ),
        "restart_after_failure": (
            _text(evidence, "service_recovery") == "active"
            and recovery_inspect.get("State", {}).get("Running") is True
            and recovery_inspect.get("Path") == "/usr/bin/sl-phase1-fixture"
            and "/usr/bin/sl-phase1-fixture" in _text(evidence, "process_relationships_recovery")
        ),
        "final_shutdown_clean": _text(evidence, "service_stop_final") == "inactive" and _record(evidence, "container_exists_final")["exit_code"] not in (None, 0),
        "no_related_avc": audit_valid and not any(any(token in line for token in related_tokens) for line in avcs),
        "complete_lifecycle": report.get("qemu_exit_code") == 0 and any(marker in serial_text for marker in ("reboot: Power down", "Powering off")),
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "all_passed": not failed,
        "failed": failed,
        "measured_scope": "disposable Candidate C --rootfs feasibility only",
        "unproven": [
            "production deployment-rootfs construction and packaging",
            "trusted reset/verifier and continuous spawn exclusion",
            "dedicated production SELinux types and policy",
            "private rootless networking with egress/DNS policy",
            "update/rollback and A-B-A lifecycle",
            "general OCI image lifecycle or Management Plane orchestration",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=Path, nargs="?")
    parser.add_argument("fixture_disk", type=Path, nargs="?")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evaluate-report", type=Path)
    parser.add_argument("--ovmf-code", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"))
    parser.add_argument("--ovmf-vars", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_VARS.fd"))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if args.evaluate_report:
        report = json.loads(args.evaluate_report.read_text())
        raw = args.evaluate_report.with_name("guest-evidence.tsv")
        if raw.exists() and records(raw) != report.get("evidence"):
            raise SystemExit("strict raw evidence does not match report.json")
        serial = args.evaluate_report.with_name("serial.log")
        result = evaluate(report, serial.read_text(errors="replace") if serial.exists() else "")
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["all_passed"] else 1)
    if args.disk is None or args.fixture_disk is None or args.output is None:
        parser.error("disk, fixture_disk and --output are required")
    before_base = sha256(args.disk)
    before_fixture = sha256(args.fixture_disk)
    if before_base != EXPECTED_BASE_QCOW2_SHA256 or before_fixture != EXPECTED_FIXTURE_DISK_SHA256:
        raise SystemExit("immutable input checksum mismatch")
    args.output.mkdir(parents=True, exist_ok=False)
    overlay = args.output / "overlay.qcow2"
    vars_copy = args.output / "OVMF_VARS.fd"
    serial = args.output / "serial.log"
    evidence_path = args.output / "guest-evidence.tsv"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(args.disk.resolve()), str(overlay)], check=True)
    shutil.copy2(args.ovmf_vars, vars_copy)
    probe = Path(__file__).with_name("guest-probe.sh").read_bytes()
    credentials = {
        "systemd.extra-unit.sl-candidate-c-probe.service": b"""[Unit]\nDescription=Candidate C feasibility probe\nDefaultDependencies=no\nConditionPathExists=!/etc/initrd-release\nAfter=multi-user.target\n[Service]\nType=oneshot\nImportCredential=sl-candidate-c-probe.sh\nExecStart=/usr/bin/bash %d/sl-candidate-c-probe.sh\nTimeoutStartSec=840\nStandardOutput=journal+console\nStandardError=journal+console\n""",
        "systemd.unit-dropin.multi-user.target": b"[Unit]\nWants=sl-candidate-c-probe.service\n",
        "sl-candidate-c-probe.sh": probe,
    }
    command = [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "4096",
        "-display", "none", "-monitor", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={vars_copy}",
        "-drive", f"if=none,id=os,format=qcow2,file={overlay}", "-device", "virtio-blk-pci,drive=os",
        "-drive", f"if=none,id=fixture,format=raw,readonly=on,file={args.fixture_disk.resolve()}", "-device", "virtio-blk-pci,drive=fixture",
        "-nic", "user,model=virtio-net-pci,mac=52:54:00:04:02:01", "-serial", f"file:{serial}",
        "-device", "virtio-serial-pci", "-chardev", f"file,id=evidence,path={evidence_path}",
        "-device", "virtserialport,chardev=evidence,name=org.signallayer.candidatec",
    ]
    for name, value in credentials.items():
        command += ["-smbios", f"type=11,value=io.systemd.credential.binary:{name}={base64.b64encode(value).decode()}"]
    started = time.monotonic()
    process = subprocess.Popen(command)
    try:
        process.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise SystemExit("Candidate C VM timed out")
    after_base = sha256(args.disk)
    after_fixture = sha256(args.fixture_disk)
    evidence = records(evidence_path)
    report = {
        "command": command,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "qemu_exit_code": process.returncode,
        "base_qcow2_sha256_before": before_base,
        "base_qcow2_sha256_after": after_base,
        "fixture_disk_sha256_before": before_fixture,
        "fixture_disk_sha256_after": after_fixture,
        "evidence": evidence,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    result = evaluate(report, serial.read_text(errors="replace") if serial.exists() else "")
    (args.output / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"qemu_exit_code": process.returncode, "evidence_keys": len(evidence), "evaluation": result}, indent=2))
    if not result["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
