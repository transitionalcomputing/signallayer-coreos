#!/usr/bin/env python3
"""Boot the Phase 1 Pass 1 disposable two-boot KVM experiment."""
import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path


DENIAL_KEYS = {
    "attack_unit_replace",
    "attack_unit_dropin",
    "attack_storage_config",
    "attack_systemctl_stop",
    "attack_systemctl_start",
    "attack_user_manager",
    "attack_rootful_socket",
    "attack_rootless_socket",
    "attack_privileged_state",
    "attack_boot_state",
    "attack_systemctl_after_reboot",
    "rootless_socket_host_api",
    "rootless_socket_host_api_after",
}

POSITIVE_KEYS = {
    "pinned_origin", "kernel", "os_release", "pid1", "systemd", "selinux",
    "selinux_policy", "cgroup_mount", "podman_version", "crun_version",
    "accounts_before", "subuid_before", "subgid_before", "fixture_archive_sha",
    "fixture_provenance", "identity", "passwd_entry", "shadow_entry",
    "subuid_after", "subgid_after", "unit_before_reboot", "unit_security",
    "unit_properties", "rootless_info", "container_inspect", "container_uid_map",
    "container_gid_map", "container_status", "container_selinux",
    "container_cgroup", "fixture_log", "hostile_user_config", "boot_id_before",
    "boot_id_after", "service_after_reboot", "service_enabled", "unit_after_reboot",
    "failed_units", "selinux_after", "rootless_info_after",
    "container_inspect_after", "fixture_log_after", "journal", "complete",
    "rootless_socket_metadata", "rootless_socket_metadata_after",
    "rootless_socket_kernel", "rootless_socket_kernel_after",
    "rootless_socket_container_view", "rootless_socket_container_view_after",
}

EXPECTED_BASE_ORIGIN = "localhost/sl-phase1-base:pass1"
EXPECTED_BASE_MANIFEST = "sha256:be66d07ce8114567d275a4c92b71a6eb0efb60023f73cfc33727e99355a0b5cb"
EXPECTED_BASE_QCOW2_SHA256 = "60a0eeef6d8f1063f99979cf576bb4a2992a0a1530cba33b2d9b1ef660560cef"
EXPECTED_FIXTURE_DISK_SHA256 = "73d26643bcdb3dc9902d4cd292e19b68d067e16aa984ebecc2dd930193ab2491"
EXPECTED_FIXTURE_ARCHIVE_SHA256 = "b821320317e12471d649ed5a33a068219c45bc7349840a4e978f6f4c8bdd35d1"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def records(path):
    result = {}
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
    starts = [position for position in (output.find("{"), output.find("[")) if position >= 0]
    if not starts:
        return None
    try:
        value, end = json.JSONDecoder().raw_decode(output[min(starts):])
    except json.JSONDecodeError:
        return None
    if output[min(starts) + end:].strip():
        return None
    return value


def _key_values(evidence, key):
    if not _ok(evidence, key):
        return None
    result = {}
    for line in _record(evidence, key)["output"].splitlines():
        if "=" not in line:
            return None
        name, value = line.split("=", 1)
        if not name or name in result:
            return None
        result[name] = value
    return result or None


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


def _inspect(evidence, key):
    value = _json_output(evidence, key)
    return value[0] if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict) else {}


def _info(evidence, key):
    value = _json_output(evidence, key)
    return value if isinstance(value, dict) else {}


def evaluate(report, serial_text):
    """Evaluate the complete stopped-VM report; never infer success from presence."""
    evidence = report.get("evidence") if isinstance(report, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    info = _info(evidence, "rootless_info")
    info_after = _info(evidence, "rootless_info_after")
    inspect = _inspect(evidence, "container_inspect")
    inspect_after = _inspect(evidence, "container_inspect_after")
    origin = _json_output(evidence, "pinned_origin")
    origin = origin if isinstance(origin, dict) else {}

    def maps(info_value, kind, host_id):
        values = info_value.get("host", {}).get("idMappings", {}).get(kind, [])
        return values == [
            {"container_id": 0, "host_id": host_id, "size": 1},
            {"container_id": 1, "host_id": 100000, "size": 65536},
        ]

    passwd = _text(evidence, "passwd_entry")
    passwd_fields = passwd.split(":")
    try:
        uid = int(passwd_fields[2])
        gid = int(passwd_fields[3])
    except (IndexError, ValueError):
        uid = gid = -1

    def info_storage(value):
        store = value.get("store", {})
        return (
            store.get("configFile") == "/etc/containers/storage-sl-management.conf"
            and store.get("graphRoot") == "/var/lib/sl-management/containers/storage"
            and store.get("runRoot") == "/run/sl-management/containers"
        )

    def native_overlay(value):
        store = value.get("store", {})
        return store.get("graphDriverName") == "overlay" and store.get("graphStatus", {}).get("Native Overlay Diff") == "true"

    def constrained(value):
        host = value.get("HostConfig", {})
        return (
            value.get("Mounts") == []
            and host.get("Binds") == []
            and host.get("NetworkMode") == "none"
            and host.get("Privileged") is False
            and host.get("ReadonlyRootfs") is True
            and "no-new-privileges" in host.get("SecurityOpt", [])
            and host.get("CapAdd") == []
            and host.get("Devices") == []
        )

    def running_fixed(value, digest):
        command = value.get("Config", {}).get("CreateCommand", [])
        return (
            value.get("State", {}).get("Running") is True
            and value.get("ImageDigest") == digest
            and value.get("ImageName", "").endswith("@" + digest)
            and isinstance(command, list)
            and bool(command)
            and command[-1].endswith("@" + digest)
        )

    def metadata_complete(value):
        if value == {"exists": "0"}:
            return True
        required = {"exists", "type", "mode", "uid", "gid", "selinux"}
        return (
            isinstance(value, dict)
            and set(value) == required
            and value["exists"] == "1"
            and all(value[name] for name in ("type", "mode", "uid", "gid", "selinux"))
            and value["mode"].isdigit()
            and value["uid"].isdigit()
            and value["gid"].isdigit()
        )

    def kernel_state_complete(value):
        if value == {"present": "0"}:
            return True
        return (
            isinstance(value, dict)
            and value.get("present") == "1"
            and any(name.startswith("entry") and entry for name, entry in value.items())
        )

    def api_observation_complete(key):
        record = _record(evidence, key)
        if record["exit_code"] == 0:
            return _json_output(evidence, key) is not None
        output = record["output"].lower()
        return (
            isinstance(record["exit_code"], int)
            and record["exit_code"] > 0
            and "/run/sl-management/podman/podman.sock" in output
            and any(message in output for message in ("connect", "dial unix", "no such file", "connection refused"))
            and "command not found" not in output
        )

    provenance = _text(evidence, "fixture_provenance")
    match = re.search(r"^fixture_manifest=(sha256:[0-9a-f]{64})$", provenance, re.MULTILINE)
    digest = match.group(1) if match else ""
    status = _text(evidence, "container_status")
    zero_caps = all(f"{name}:\t0000000000000000" in status for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    unit_properties = _text(evidence, "unit_properties")
    unit_before = _text(evidence, "unit_before_reboot")
    unit_after = _text(evidence, "unit_after_reboot")
    journal = _text(evidence, "journal")
    audit_valid, audit_messages = _audit_messages(evidence)
    socket_metadata = [_key_values(evidence, key) for key in ("rootless_socket_metadata", "rootless_socket_metadata_after")]
    socket_kernel = [_key_values(evidence, key) for key in ("rootless_socket_kernel", "rootless_socket_kernel_after")]
    socket_container = [_key_values(evidence, key) for key in ("rootless_socket_container_view", "rootless_socket_container_view_after")]

    socket_api_valid = all(api_observation_complete(key) for key in ("rootless_socket_host_api", "rootless_socket_host_api_after"))
    required_commands = all(_ok(evidence, key) for key in POSITIVE_KEYS) and audit_valid and socket_api_valid
    denied_commands = all(_record(evidence, key)["exit_code"] not in (None, 0) for key in DENIAL_KEYS)
    expected_negative = (
        _record(evidence, "login_state")["exit_code"] not in (None, 0)
        and _record(evidence, "user_manager")["exit_code"] not in (None, 0)
    )
    system_state = _record(evidence, "system_state")
    system_state_valid = (system_state["exit_code"], system_state["output"].strip()) in {(0, "running"), (1, "starting")}

    command = report.get("command", []) if isinstance(report, dict) else []
    booted_image = origin.get("status", {}).get("booted", {}).get("image", {})
    fixed_unit_lines = (
        "User=sl-management",
        "Group=sl-management",
        "Environment=XDG_RUNTIME_DIR=/run/sl-management",
        "--pull=never --network=none --read-only --security-opt=no-new-privileges --cap-drop=all",
        "Delegate=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
    )
    avcs = [line.lower() for line in serial_text.splitlines() if "avc:" in line.lower() and "denied" in line.lower()]
    avcs.extend(message.lower() for message in audit_messages if "avc:" in message.lower() and "denied" in message.lower())
    related = ("sl-management", "sl-phase1", "container_t", 'comm="podman"', 'comm="crun"', 'comm="conmon"')
    checks = {
        "qemu_clean_exit": report.get("qemu_exit_code") == 0,
        "probe_complete": _ok(evidence, "complete") and _text(evidence, "complete") == "pass1 probe complete" and "failure" not in evidence,
        "evidence_commands_valid": required_commands and denied_commands and expected_negative and system_state_valid,
        "journal_avc_evidence_valid": audit_valid,
        "genuine_kvm": (
            report.get("qemu_exit_code") == 0
            and "q35,accel=kvm" in command
            and "host" in command
            and report.get("base_qcow2_sha256") == EXPECTED_BASE_QCOW2_SHA256
            and report.get("fixture_disk_sha256") == EXPECTED_FIXTURE_DISK_SHA256
            and any("id=fixture" in item and "readonly=on" in item for item in command)
        ),
        "pinned_base": (
            booted_image.get("image", {}).get("image") == EXPECTED_BASE_ORIGIN
            and booted_image.get("imageDigest") == EXPECTED_BASE_MANIFEST
        ),
        "pid1_systemd": _ok(evidence, "pid1") and _text(evidence, "pid1") == "systemd",
        "fedora_44": _ok(evidence, "os_release") and 'VERSION_ID=44' in _text(evidence, "os_release"),
        "kernel_7_2_7": _ok(evidence, "kernel") and "7.2.7-200.fc44.x86_64" in _text(evidence, "kernel"),
        "selinux_enforcing": _text(evidence, "selinux") == "Enforcing" and _text(evidence, "selinux_after") == "Enforcing",
        "cgroup_v2": _ok(evidence, "cgroup_mount") and _text(evidence, "cgroup_mount").startswith("cgroup2 ") and "nsdelegate" in _text(evidence, "cgroup_mount"),
        "podman_5_8_7": _ok(evidence, "podman_version") and "Version:       5.8.7" in _text(evidence, "podman_version"),
        "crun_1_28": _ok(evidence, "crun_version") and "crun version 1.28" in _text(evidence, "crun_version") and all(item in _text(evidence, "crun_version") for item in ("+SYSTEMD", "+SELINUX", "+CAP", "+SECCOMP")),
        "locked_nologin": len(passwd_fields) >= 7 and passwd_fields[0] == "sl-management" and passwd_fields[6] == "/usr/sbin/nologin" and _text(evidence, "shadow_entry").startswith("sl-management:!"),
        "subuid": _text(evidence, "subuid_after") == "sl-management:100000:65536",
        "subgid": _text(evidence, "subgid_after") == "sl-management:100000:65536",
        "rootless": all(value.get("host", {}).get("security", {}).get("rootless") is True for value in (info, info_after)),
        "native_overlay": native_overlay(info) and native_overlay(info_after),
        "explicit_store": info_storage(info) and info_storage(info_after),
        "uid_map": uid > 0 and maps(info, "uidmap", uid) and maps(info_after, "uidmap", uid) and _text(evidence, "container_uid_map").split() == ["0", str(uid), "1", "1", "100000", "65536"],
        "gid_map": gid > 0 and maps(info, "gidmap", gid) and maps(info_after, "gidmap", gid) and _text(evidence, "container_gid_map").split() == ["0", str(gid), "1", "1", "100000", "65536"],
        "zero_caps_nnp": zero_caps and "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status and all(value.get("EffectiveCaps") is None and value.get("BoundingCaps") is None for value in (inspect, inspect_after)),
        "container_selinux": "container_t:" in _text(evidence, "container_selinux") and all("container_t:" in value.get("ProcessLabel", "") for value in (inspect, inspect_after)),
        "delegated_service_cgroup": "Delegate=yes" in unit_properties and "ControlGroup=/system.slice/sl-management-fixture.service" in unit_properties and _text(evidence, "container_cgroup") == "0::/system.slice/sl-management-fixture.service" and all(value.get("State", {}).get("CgroupPath") == "/system.slice/sl-management-fixture.service" for value in (inspect, inspect_after)),
        "fixed_image": bool(digest) and running_fixed(inspect, digest) and running_fixed(inspect_after, digest),
        "fixture_archive_integrity": (
            _text(evidence, "fixture_archive_sha").split()[:1] == [EXPECTED_FIXTURE_ARCHIVE_SHA256]
            and bool(digest)
        ),
        "fixed_unit_contract": unit_before == unit_after and all(line in unit_before for line in fixed_unit_lines),
        "container_constraints": constrained(inspect) and constrained(inspect_after) and all(
            marker in journal for marker in (
                "privileged_write=Read-only file system",
                "socket:/run/podman/podman.sock=No such file or directory",
                "socket:/run/systemd/private=No such file or directory",
            )
        ),
        "reboot_restart": _ok(evidence, "boot_id_before") and _ok(evidence, "boot_id_after") and _text(evidence, "boot_id_before") != _text(evidence, "boot_id_after") and _text(evidence, "service_after_reboot") == "active" and _text(evidence, "service_enabled") == "enabled" and inspect_after.get("State", {}).get("Running") is True,
        "no_login_or_user_manager": expected_negative and "/usr/sbin/nologin" in passwd and _text(evidence, "user_manager") == "inactive",
        "rootless_socket_diagnostics_complete": (
            all(metadata_complete(value) for value in socket_metadata + socket_container)
            and all(kernel_state_complete(value) for value in socket_kernel)
            and socket_api_valid
        ),
        "host_rootless_socket_absent": (
            all(value == {"exists": "0"} for value in socket_metadata)
            and all(value == {"present": "0"} for value in socket_kernel)
            and all(_record(evidence, key)["exit_code"] not in (None, 0) for key in ("rootless_socket_host_api", "rootless_socket_host_api_after"))
            and _record(evidence, "attack_rootless_socket")["exit_code"] not in (None, 0)
        ),
        "container_rootless_socket_inaccessible": all(value == {"exists": "0"} for value in socket_container),
        "authority_attacks_denied": denied_commands,
        "no_failed_units": _ok(evidence, "failed_units") and not _text(evidence, "failed_units") and system_state_valid,
        "no_related_avc": bool(serial_text) and not any(any(token in line for token in related) for line in avcs),
        "complete_two_boot_lifecycle": "reboot: Power down" in serial_text and _text(evidence, "boot_id_before") != _text(evidence, "boot_id_after"),
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "checks": checks,
        "passed": sum(checks.values()),
        "total": len(checks),
        "all_passed": not failed,
        "failed": failed,
        "unproven": [
            "identity collision/malformed/interrupted/retry cases",
            "immutable additional image store",
            "dedicated SELinux domain",
            "private rootless networking",
            "deliberate runtime failure isolation",
            "A-B-A lifecycle and independent CoreOS recovery",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=Path, nargs="?")
    parser.add_argument("fixture_disk", type=Path, nargs="?")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evaluate-report", type=Path, help="evaluate a completed report.json without starting QEMU")
    parser.add_argument("--ovmf-code", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"))
    parser.add_argument("--ovmf-vars", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_VARS.fd"))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if args.evaluate_report:
        report = json.loads(args.evaluate_report.read_text())
        raw_evidence = args.evaluate_report.with_name("guest-evidence.tsv")
        if raw_evidence.exists() and records(raw_evidence) != report.get("evidence"):
            raise SystemExit("strict raw evidence does not match report.json")
        serial_path = args.evaluate_report.with_name("serial.log")
        evaluation = evaluate(report, serial_path.read_text(errors="replace") if serial_path.exists() else "")
        print(json.dumps(evaluation, indent=2))
        raise SystemExit(0 if evaluation["all_passed"] else 1)
    if args.disk is None or args.fixture_disk is None or args.output is None:
        parser.error("disk, fixture_disk, and --output are required unless --evaluate-report is used")
    args.output.mkdir(parents=True, exist_ok=True)
    overlay = args.output / "overlay.qcow2"
    vars_copy = args.output / "OVMF_VARS.fd"
    serial = args.output / "serial.log"
    evidence_path = args.output / "guest-evidence.tsv"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(args.disk.resolve()), str(overlay)], check=True)
    shutil.copy2(args.ovmf_vars, vars_copy)
    probe = Path(__file__).with_name("guest-probe.sh").read_bytes()
    credentials = {
        "systemd.extra-unit.sl-phase1-probe.service": b"""[Unit]\nDescription=Phase 1 Pass 1 probe\nDefaultDependencies=no\nConditionPathExists=!/etc/initrd-release\nAfter=multi-user.target\n[Service]\nType=oneshot\nImportCredential=sl-phase1-probe.sh\nExecStart=/usr/bin/bash %d/sl-phase1-probe.sh\nTimeoutStartSec=840\nStandardOutput=journal+console\nStandardError=journal+console\n""",
        "systemd.unit-dropin.multi-user.target": b"[Unit]\nWants=sl-phase1-probe.service\n",
        "sl-phase1-probe.sh": probe,
    }
    command = [
        "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "4096",
        "-display", "none", "-monitor", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}",
        "-drive", f"if=pflash,format=raw,file={vars_copy}",
        "-drive", f"if=none,id=os,format=qcow2,file={overlay}", "-device", "virtio-blk-pci,drive=os",
        "-drive", f"if=none,id=fixture,format=raw,readonly=on,file={args.fixture_disk.resolve()}", "-device", "virtio-blk-pci,drive=fixture",
        "-nic", "user,model=virtio-net-pci,mac=52:54:00:04:01:01",
        "-serial", f"file:{serial}",
        "-device", "virtio-serial-pci", "-chardev", f"file,id=evidence,path={evidence_path}",
        "-device", "virtserialport,chardev=evidence,name=org.signallayer.phase1",
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
        raise SystemExit("Phase 1 VM timed out")
    evidence = records(evidence_path)
    report = {
        "command": command,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "qemu_exit_code": process.returncode,
        "base_qcow2_sha256": sha256(args.disk),
        "fixture_disk_sha256": sha256(args.fixture_disk),
        "evidence": evidence,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    evaluation = evaluate(report, serial.read_text(errors="replace") if serial.exists() else "")
    (args.output / "evaluation.json").write_text(json.dumps(evaluation, indent=2) + "\n")
    print(json.dumps({"qemu_exit_code": process.returncode, "evidence_keys": len(evidence), "evaluation": evaluation}, indent=2))
    if not evaluation["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
