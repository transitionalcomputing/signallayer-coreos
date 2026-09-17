#!/usr/bin/env python3
"""Bounded UEFI disk boot on native Linux, with serial and guest evidence."""
import argparse
import base64
import configparser
import hashlib
import json
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def records(path):
    found = {}
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            fields = line.split("\t", 2)
            if len(fields) != 3:
                continue
            try:
                found[fields[0]] = {"exit_code": int(fields[1]), "output":
                    base64.b64decode(fields[2], validate=True).decode(errors="replace")}
            except (ValueError, UnicodeError):
                continue
    return found


def archive_identity(path, source_id):
    # Podman OCI export can change the manifest digest while preserving the
    # immutable image config ID. Validate the exact archive used by Phase 2A.
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile("index.json"))
        if len(index["manifests"]) != 1:
            raise RuntimeError("Expected a single image manifest in the Phase 2A OCI archive")
        digest = index["manifests"][0]["digest"]
        manifest = archive.extractfile("blobs/" + digest.replace(":", "/")).read()
        if digest != "sha256:" + hashlib.sha256(manifest).hexdigest():
            raise RuntimeError("OCI archive manifest checksum mismatch")
        config_digest = json.loads(manifest)["config"]["digest"]
        if config_digest.removeprefix("sha256:") != source_id.removeprefix("sha256:"):
            raise RuntimeError("OCI archive config does not match the Phase 2A source image ID")
        config = archive.extractfile("blobs/" + config_digest.replace(":", "/")).read()
        if config_digest != "sha256:" + hashlib.sha256(config).hexdigest():
            raise RuntimeError("OCI archive config checksum mismatch")
        configuration = json.loads(config)
        if (configuration["os"], configuration["architecture"]) != ("linux", "amd64"):
            raise RuntimeError("OCI archive payload must be linux/amd64")
    return {"path": str(path.resolve()), "manifest_digest": digest, "config_digest": config_digest}


def evaluate(evidence, expected_release, expected_manifest):
    def text(key):
        return evidence.get(key, {}).get("output", "").strip()

    def ok(key):
        return evidence.get(key, {}).get("exit_code") == 0

    checks = {
        "probe_complete": ok("complete"),
        "pid1_systemd": ok("pid1") and text("pid1") == "systemd",
        "operational_target": ok("target") and text("target") == "active",
        "system_running": ok("system_state") and text("system_state") == "running",
        "no_failed_units": ok("failed_units") and not text("failed_units"),
        "network_manager_active": ok("network_manager") and text("network_manager") == "active",
        "expected_release": ok("release") and evidence["release"]["output"] == expected_release,
        "ostree_booted": ok("ostree_booted") and "ostree=" in text("cmdline"),
        "selinux_enforcing": ok("selinux") and text("selinux") == "Enforcing",
        "root_rejects_writes": not ok("root_write") and "Read-only file system" in text("root_write"),
        "usr_rejects_writes": not ok("usr_write") and "Read-only file system" in text("usr_write"),
    }
    try:
        addresses = json.loads(text("addresses"))
        routes = json.loads(text("routes"))
        checks["network_address_and_route"] = ok("addresses") and ok("routes") and any(
            device["ifname"] != "lo" and device.get("operstate") == "UP" and any(
                address.get("family") == "inet" and address.get("scope") == "global"
                for address in device.get("addr_info", [])) for device in addresses) and any(
            route.get("dst") == "default" and route.get("gateway") for route in routes)
    except (ValueError, KeyError, TypeError):
        checks["network_address_and_route"] = False
    try:
        booted = json.loads(text("bootc_status"))["status"]["booted"]
        checks["expected_bootc_deployment"] = ok("bootc_status") and bool(booted["ostree"]["checksum"]) and (
            booted["image"]["image"]["image"] == "localhost/signallayer-coreos:0.0.1")
        checks["source_manifest_matches"] = booted["image"]["imageDigest"] == expected_manifest
        checks["ostree_status_matches"] = ok("ostree_status") and (
            "* default " + booted["ostree"]["checksum"] + "." in text("ostree_status"))
    except (ValueError, KeyError, TypeError):
        checks["expected_bootc_deployment"] = False
        checks["source_manifest_matches"] = False
        checks["ostree_status_matches"] = False
    try:
        configuration = configparser.ConfigParser()
        configuration.read_string(text("prepare_root"))
        checks["immutable_configuration"] = ok("prepare_root") and (
            configuration.get("composefs", "enabled") in ("yes", "true", "1") and
            configuration.getboolean("sysroot", "readonly") and
            not configuration.getboolean("root", "transient", fallback=False))
        mounts = {}

        def visit(entries):
            for entry in entries:
                mounts[entry["target"]] = entry
                visit(entry.get("children", []))

        visit(json.loads(text("mounts"))["filesystems"])
        root = mounts["/"]
        checks["runtime_composefs"] = ok("mounts") and root["fstype"] == "overlay" and (
            "composefs" in root["source"] or "composefs" in text("prepare_root_journal").lower())
        checks["root_and_sysroot_readonly"] = all(
            "ro" in mounts[target]["options"].split(",") for target in ("/", "/sysroot"))
    except (ValueError, KeyError, TypeError, configparser.Error):
        checks["immutable_configuration"] = False
        checks["runtime_composefs"] = False
        checks["root_and_sysroot_readonly"] = False
    return checks


def evaluate_platform(evidence, expected_release):
    def text(key):
        return evidence.get(key, {}).get("output", "").strip()

    def ok(key):
        return evidence.get(key, {}).get("exit_code") == 0

    checks = {
        "platform_active": ok("platform_active") and text("platform_active") == "active",
        "platform_human": ok("platform_human") and "SignalLayerIT CoreOS 0.0.1" in text("platform_human"),
        "platform_unprivileged_uid": ok("platform_unprivileged_uid") and text("platform_unprivileged_uid").isdigit() and int(text("platform_unprivileged_uid")) != 0,
        "platform_restored": all(ok(key) for key in (
            "platform_stop", "platform_restart", "platform_test_reload", "platform_backend_restart",
            "platform_capability_reload", "platform_capability_restart", "platform_restore_reload", "platform_restore_restart", "platform_final_active")) and text("platform_final_active") == "active",
        "platform_final_system_running": ok("platform_final_system_state") and text("platform_final_system_state") == "running" and ok("platform_final_failed_units") and not text("platform_final_failed_units"),
    }
    try:
        unit = dict(line.split("=", 1) for line in text("platform_unit").splitlines())
        checks["platform_unit_privileges"] = ok("platform_unit") and all(unit.get(key) == value for key, value in {
            "User": "root", "NoNewPrivileges": "yes",
            "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes"}.items()) and set(unit.get("CapabilityBoundingSet", "").split()) == {"cap_sys_admin", "cap_sys_ptrace"}
        checks["platform_unprivileged_backend_denied"] = not ok("platform_unprivileged_backend_start") and ok("platform_unprivileged_backend") and "This command must be executed as the root user" in text("platform_unprivileged_backend")
        messages = [json.loads(line) for line in text("platform_unprivileged_json_metadata").splitlines()]
        checks["platform_unprivileged_client_proven"] = ok("platform_unprivileged_uid_start") and ok("platform_unprivileged_json_start") and ok("platform_unprivileged_json_metadata") and bool(messages) and all(int(message["_UID"]) != 0 and message["_COMM"] == "corectl" and message["_SYSTEMD_UNIT"] == "slprobe-unpriv-json.service" and message.get("_EXE", "/usr/bin/corectl") == "/usr/bin/corectl" for message in messages)
        after = dict(evidence)
        for old, new in (("mounts", "platform_final_mounts"), ("root_write", "platform_final_root_write"), ("usr_write", "platform_final_usr_write")):
            after[old] = evidence.get(new, {})
        immutable = evaluate(after, expected_release, "unused")
        for key in ("runtime_composefs", "root_and_sysroot_readonly", "root_rejects_writes", "usr_rejects_writes"):
            checks["platform_after_" + key] = immutable[key]
        release = dict(line.split("=", 1) for line in expected_release.splitlines() if line)
        release = {key: value.strip('"') for key, value in release.items()}
        backend = json.loads(text("bootc_status"))["status"]

        def deployment(value):
            image = value.get("image")
            return {"deployment_id": value["ostree"]["checksum"] + "." + str(value["ostree"]["deploySerial"]),
                    "image_reference": image["image"]["image"] if image else None,
                    "image_digest": image["imageDigest"] if image else None}

        expected = {"schema_version": "0.1", "product": release["NAME"], "version": release["VERSION"],
                    "platform_api_version": release["PLATFORM_API_VERSION"],
                    "source_revision": None if release.get("SOURCE_REVISION", "unknown") == "unknown" else release["SOURCE_REVISION"],
                    "build_id": None if release.get("BUILD_ID", "unknown") == "unknown" else release["BUILD_ID"],
                    "booted": deployment(backend["booted"]),
                    "retained_rollback": deployment(backend["rollback"]) if backend["rollback"] else None,
                    "health": {"state": "healthy", "system_state": "running", "failed_units": 0}}
        for key in ("platform_json", "platform_unprivileged_json", "platform_final_json"):
            checks[key + "_matches_observations"] = ok(key) and json.loads(text(key)) == expected
        for key, code in (("platform_service_error", "ServiceUnavailable"), ("platform_backend_error", "BackendUnavailable"), ("platform_capability_error", "BackendUnavailable")):
            error = json.loads(text(key))["error"]
            checks[key] = not ok(key) and error["code"] == code and bool(error["message"])
    except (ValueError, KeyError, TypeError):
        checks["platform_evidence_valid"] = False
    return checks


class QMP:
    def __init__(self, path, log):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(3)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb", buffering=0)
        self.log = log
        self.read()
        self.command("qmp_capabilities")

    def read(self):
        line = self.stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        message = json.loads(line)
        with self.log.open("a") as log:
            log.write(json.dumps(message) + "\n")
        return message

    def command(self, name):
        self.stream.write(json.dumps({"execute": name, "id": name}).encode() + b"\n")
        while True:
            message = self.read()
            if message.get("id") == name:
                if "error" in message:
                    raise RuntimeError(str(message["error"]))
                return message.get("return")

    def close(self):
        self.stream.close()
        self.socket.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=Path)
    parser.add_argument("--phase3a", action="store_true", help="Also validate the read-only platform service and CLI")
    parser.add_argument("--source-release", type=Path)
    parser.add_argument("--source-image", type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    args = parser.parse_args()
    output = Path(__file__).resolve().parents[2] / "image/build/output"
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="phase3a-" if args.phase3a else "phase2b-", dir=output))
    report = {"phase": "3A" if args.phase3a else "2B", "result": "FAIL", "output": str(run), "checks": {}}
    process = None
    qmp = None
    disk_hash = None
    handles = []
    print(f"Boot report: {run}", flush=True)
    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise RuntimeError("Boot validation requires native x86_64 Linux")
        if args.timeout < 1:
            raise RuntimeError("Timeout must be positive")
        for tool in ("qemu-system-x86_64", "qemu-img"):
            if not shutil.which(tool):
                raise RuntimeError(f"Required executable missing: {tool}")
        disk = args.disk.resolve(strict=True)
        release = args.source_release or disk.parent / "source-release"
        expected_release = release.read_text()
        source_image = args.source_image or disk.parent / "source-image.json"
        source = json.loads(source_image.read_text())[0]
        if not source.get("Id") or source.get("Architecture") != "amd64":
            raise RuntimeError("Phase 2A source-image.json must record an amd64 image ID")
        identity = archive_identity(args.source_archive or disk.parent / "source.oci.tar", source["Id"])
        expected_manifest = identity["manifest_digest"]
        disk_hash = checksum(disk)
        report.update(disk=str(disk), disk_sha256=disk_hash, host_kernel=platform.release(),
                      host_os=platform.freedesktop_os_release().get("PRETTY_NAME"),
                      acceleration=args.accel, timeout_seconds=args.timeout,
                      expected_release=expected_release,
                      source_oci={key: source.get(key) for key in ("Id", "Digest", "Architecture")},
                      builder_oci_archive=identity,
                      test_script_sha256=checksum(Path(__file__).resolve()))
        info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", str(disk)]))
        if info["format"] != "qcow2" or info.get("backing-filename"):
            raise RuntimeError("Input must be the self-contained Phase 2A qcow2")
        report["disk_info"] = info
        report["qemu_version"] = subprocess.check_output(["qemu-system-x86_64", "--version"], text=True)
        for key, path in (("firmware_code", args.ovmf_code), ("firmware_vars_template", args.ovmf_vars)):
            path = path.resolve(strict=True)
            report[key] = {"path": str(path), "sha256": checksum(path)}
        shutil.copyfile(args.ovmf_vars, run / "OVMF_VARS.fd")
        overlay = run / "boot.qcow2"
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(disk), str(overlay)], check=True)
        probe = Path(__file__).with_name("guest-probe.sh").read_text()
        if args.phase3a:
            extension = Path(__file__).with_name("guest-platform-probe.sh")
            marker = "printf 'complete\\t0\\tZG9uZQ==\\n' >&3"
            if probe.count(marker) != 1:
                raise RuntimeError("Boot probe completion marker is missing or ambiguous")
            probe = probe.replace(marker, extension.read_text() + "\n" + marker)
            report["platform_probe_sha256"] = checksum(extension)
        unit = """[Unit]
Description=Temporary CoreOS boot evidence probe
DefaultDependencies=no
ConditionPathExists=!/etc/initrd-release
After=multi-user.target NetworkManager.service
[Service]
Type=simple
ImportCredential=slprobe.sh
ExecStart=/usr/bin/bash %d/slprobe.sh
StandardOutput=journal+console
StandardError=journal+console
"""
        credentials = {
            "systemd.extra-unit.slprobe.service": unit,
            "systemd.unit-dropin.multi-user.target": "[Unit]\nWants=slprobe.service\n",
            "slprobe.sh": probe,
        }
        command = ["qemu-system-x86_64", "-machine", f"q35,accel={args.accel}",
            "-cpu", "host" if args.accel == "kvm" else "max", "-smp", "2", "-m", "2048",
            "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code.resolve()}",
            "-drive", f"if=pflash,format=raw,file={run}/OVMF_VARS.fd",
            "-drive", f"if=none,id=os,format=qcow2,file={overlay}", "-device", "virtio-blk-pci,drive=os",
            "-nic", "user,model=virtio-net-pci,mac=52:54:00:00:02:0b",
            "-display", "none", "-monitor", "none", "-serial", f"file:{run}/serial.log",
            "-qmp", f"unix:{run}/qmp.sock,server=on,wait=off",
            "-device", "virtio-serial-pci", "-chardev", f"file,id=evidence,path={run}/guest-evidence.tsv",
            "-device", "virtserialport,chardev=evidence,name=org.signallayer.boot-test", "-no-reboot"]
        for name, value in credentials.items():
            encoded = base64.b64encode(value.encode()).decode()
            command += ["-smbios", f"type=11,value=io.systemd.credential.binary:{name}={encoded}"]
        # QEMU comma-delimited file options require escaped commas; reject
        # such paths rather than accidentally interpreting extra options.
        if any("," in str(path) for path in (disk, run, args.ovmf_code, args.ovmf_vars)):
            raise RuntimeError("QEMU test paths must not contain commas")
        (run / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
        (run / "qemu-command.sh").write_text(shlex.join(command) + "\n")
        (run / "probe.service").write_text(unit)
        (run / "guest-probe.sh").write_text(probe)
        for name in ("qemu.stdout", "qemu.stderr"):
            handles.append((run / name).open("wb"))
        process = subprocess.Popen(command, stdout=handles[0], stderr=handles[1])
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"QEMU exited before evidence completed: {process.returncode}")
            if qmp is None and (run / "qmp.sock").exists():
                qmp = QMP(run / "qmp.sock", run / "qmp.jsonl")
                report["qmp_boot_status"] = qmp.command("query-status")
            evidence = records(run / "guest-evidence.tsv")
            if "complete" in evidence:
                report["checks"] = evaluate(evidence, expected_release, expected_manifest)
                if args.phase3a:
                    report["checks"].update(evaluate_platform(evidence, expected_release))
                (run / "guest-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(f"Guest evidence timeout after {args.timeout} seconds")
        if qmp is None:
            raise RuntimeError("No QMP connection established")
        report["qmp_final_status"] = qmp.command("query-status")
        qmp.command("system_powerdown")
        try:
            process.wait(timeout=30)
            report["guest_powered_down"] = process.returncode == 0
        except subprocess.TimeoutExpired:
            report["guest_powered_down"] = False
            qmp.command("quit")
            process.wait(timeout=10)
        report["result"] = "PASS" if all(report["checks"].values()) else "FAIL"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, tarfile.TarError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if qmp is not None:
            qmp.close()
        for handle in handles:
            handle.close()
        evidence = records(run / "guest-evidence.tsv")
        (run / "guest-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        if disk_hash is not None:
            report["source_disk_unchanged"] = checksum(args.disk.resolve()) == disk_hash
            if not report["source_disk_unchanged"]:
                report["result"] = "FAIL"
        (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
