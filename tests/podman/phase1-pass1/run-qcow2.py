#!/usr/bin/env python3
"""Boot the Phase 1 Pass 1 disposable two-boot KVM experiment."""
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def records(path):
    result = {}
    for line in path.read_text(errors="replace").splitlines() if path.exists() else []:
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        try:
            result[fields[0]] = {
                "exit_code": int(fields[1]),
                "output": base64.b64decode(fields[2], validate=True).decode(errors="replace"),
            }
        except (ValueError, UnicodeError):
            continue
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=Path)
    parser.add_argument("fixture_disk", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ovmf-code", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"))
    parser.add_argument("--ovmf-vars", type=Path, default=Path("/usr/share/edk2/ovmf/OVMF_VARS.fd"))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
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
    print(json.dumps({"qemu_exit_code": process.returncode, "evidence_keys": len(evidence), "complete": evidence.get("complete")}, indent=2))
    if process.returncode or evidence.get("complete", {}).get("exit_code") != 0 or "failure" in evidence:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
