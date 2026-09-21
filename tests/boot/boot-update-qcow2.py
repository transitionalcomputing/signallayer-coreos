#!/usr/bin/env python3
"""Run the bounded Phase 3C bootc staging acceptance test under KVM."""
import argparse, base64, datetime, hashlib, json, pathlib, shutil, subprocess

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()

def records(path):
    found = {}
    if not path.exists():
        return found
    for line in path.read_text(errors="replace").splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        try:
            found[fields[0]] = {"exit_code": int(fields[1]), "output": base64.b64decode(fields[2], validate=True).decode(errors="replace")}
        except (ValueError, UnicodeError):
            pass
    return found

def evaluate(evidence):
    def ok(key): return evidence.get(key, {}).get("exit_code") == 0
    def text(key): return evidence.get(key, {}).get("output", "").strip()
    def parsed(key): return json.loads(text(key))
    checks = {}
    try:
        initial = parsed("initial_bootc")["status"]
        failure = parsed("failure_bootc")["status"]
        final = parsed("final_bootc")["status"]
        status = parsed("final_corectl")
        failure_status = parsed("failure_status")
        booted = initial["booted"]
        staged = final["staged"]
        checks.update({
            "initial_has_no_staged_deployment": initial["staged"] is None,
            "failure_is_structured": failure_status["update"]["state"] == "failed" and failure_status["update"]["failure"]["code"] == "WorkerFailed",
            "failure_left_a_booted": failure["booted"]["ostree"] == booted["ostree"] and failure["staged"] is None,
            "start_update_prompt": ok("start_update") and int(text("start_update_elapsed_ns")) < 3_000_000_000,
            "concurrent_request_busy": not ok("concurrent_update") and parsed("concurrent_update")["error"]["code"] == "Busy",
            "a_remains_booted": final["booted"]["ostree"] == booted["ostree"] and final["booted"]["image"]["imageDigest"] == booted["image"]["imageDigest"],
            "b_is_staged": staged is not None and staged["ostree"] != booted["ostree"],
            "staged_is_not_download_only": staged["downloadOnly"] is False,
            "corectl_reports_staged": status["update"]["state"] == "staged" and status["update"]["reboot_required"] is True,
            "corectl_staged_identity_matches": status["update"]["staged"]["deployment_id"] == staged["ostree"]["checksum"] + "." + str(staged["ostree"]["deploySerial"]),
        })
    except (ValueError, KeyError, TypeError):
        checks["machine_readable_update_evidence"] = False
    unit = text("update_unit")
    process = text("worker_process")
    result = text("worker_result")
    checks.update({
        "probe_completed": ok("complete"),
        "fixed_unit_command": "ExecStart=/usr/bin/bootc upgrade --quiet" in unit and "--apply" not in unit and "--download-only" not in unit and "/bin/sh" not in unit and "/bin/bash" not in unit,
        "dedicated_unit_label": ok("update_unit_context") and "sl_update_unit_file_t:s0" in text("update_unit_context"),
        "fedora_bootc_entry_label": ok("bootc_exec_context") and "install_exec_t:s0" in text("bootc_exec_context"),
        "bootc_runtime_is_narrowly_labeled": ok("bootc_runtime_context") and
            "sl_bootc_runtime_t:s0" in text("bootc_runtime_context"),
        "staged_marker_is_narrowly_labeled": ok("staged_marker_expected_context") and
            text("staged_marker_expected_context") == "system_u:object_r:sl_bootc_state_t:s0" and
            ok("staged_marker_context") and "sl_bootc_state_t:s0" in text("staged_marker_context"),
        "worker_uses_install_domain": ok("worker_process") and "system_u:system_r:install_t:s0" in process,
        "worker_exact_process": "cmdline=/usr/bin/bootc upgrade --quiet " in process and "cgroup=0::/system.slice/sl-update.service" in process,
        "worker_succeeded": ok("worker_wait") and "Result=success" in result and "ExecMainStatus=0" in result,
        "failure_worker_failed": "Result=exit-code" in text("failure_result") and "ExecMainStatus=0" not in text("failure_result"),
        "boot_id_unchanged": text("boot_id_before") == text("failure_boot_id") == text("boot_id_after"),
        "operational_target_preserved": text("target_before") == text("failure_target") == text("target_after") == "active",
        "system_healthy": text("system_state_after") == "running" and not text("failed_after"),
        "selinux_enforcing": text("selinux_before") == text("failure_selinux") == text("selinux_after") == "Enforcing",
        "immutable_writes_rejected": all(not ok(key) and "Read-only file system" in text(key) for key in ("root_write_before", "usr_write_before", "root_write_after", "usr_write_after")),
        "platform_avcs_limited_to_expected_repository_probe": ok("platform_avcs") and all(
            "denied  { write }" in line and 'comm="bootc"' in line and
            'name="objects"' in line and
            "scontext=system_u:system_r:sl_platformd_t:s0" in line and
            "tclass=dir" in line and "permissive=0" in line
            for line in text("platform_avcs").splitlines()
        ),
    })
    try:
        mounts = json.loads(text("mounts_after"))["filesystems"]
        flat = {}
        def visit(items):
            for item in items:
                flat[item["target"]] = item
                visit(item.get("children", []))
        visit(mounts)
        checks["immutable_mounts_preserved"] = all("ro" in flat[path]["options"].split(",") for path in ("/", "/sysroot")) and flat["/"]["fstype"] == "overlay"
    except (ValueError, KeyError, TypeError):
        checks["immutable_mounts_preserved"] = False
    return checks

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=pathlib.Path)
    parser.add_argument("--ovmf-code", type=pathlib.Path, default=pathlib.Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"))
    parser.add_argument("--ovmf-vars", type=pathlib.Path, default=pathlib.Path("/usr/share/edk2/ovmf/OVMF_VARS.fd"))
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    disk = args.disk.resolve(strict=True)
    output = pathlib.Path(__file__).resolve().parents[2] / "image/build/output"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = output / f"phase3c-acceptance-{stamp}"
    run.mkdir(parents=True)
    probe = pathlib.Path(__file__).with_name("guest-update-probe.sh").read_bytes()
    (run / "probe.sh").write_bytes(probe)
    unit = b"""[Unit]\nDescription=Disposable Phase 3C acceptance probe\nDefaultDependencies=no\nConditionPathExists=!/etc/initrd-release\nAfter=multi-user.target NetworkManager.service\n[Service]\nType=simple\nImportCredential=phase3c-probe.sh\nExecStart=/usr/bin/bash %d/phase3c-probe.sh\nStandardOutput=journal+console\nStandardError=journal+console\nTimeoutStartSec=14min\n"""
    dropin = b"[Unit]\nWants=phase3c-probe.service\n"
    overlay = run / "boot.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(disk), str(overlay)], check=True)
    variables = run / "OVMF_VARS.fd"
    shutil.copyfile(args.ovmf_vars, variables)
    def credential(name, value): return "type=11,value=io.systemd.credential.binary:" + name + "=" + base64.b64encode(value).decode()
    command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
        "-drive", f"if=pflash,format=raw,readonly=on,file={args.ovmf_code.resolve()}", "-drive", f"if=pflash,format=raw,file={variables}",
        "-drive", f"if=none,id=os,format=qcow2,file={overlay}", "-device", "virtio-blk-pci,drive=os",
        "-nic", "user,model=virtio-net-pci,mac=52:54:00:00:03:0e", "-display", "none", "-monitor", "none",
        "-serial", f"file:{run / 'serial.log'}", "-device", "virtio-serial-pci", "-chardev", f"file,id=evidence,path={run / 'evidence.tsv'}",
        "-device", "virtserialport,chardev=evidence,name=org.signallayer.phase3c-test", "-no-reboot",
        "-smbios", credential("systemd.extra-unit.phase3c-probe.service", unit), "-smbios", credential("systemd.unit-dropin.multi-user.target", dropin),
        "-smbios", credential("phase3c-probe.sh", probe)]
    (run / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
    report = {"phase":"3C", "result":"FAIL", "output":str(run), "disk":str(disk), "disk_sha256":digest(disk),
              "probe_sha256":hashlib.sha256(probe).hexdigest(), "qemu_version":subprocess.check_output(["qemu-system-x86_64", "--version"], text=True).splitlines()[0]}
    with (run / "registry-target.json").open("wb") as target:
        subprocess.run(["skopeo", "inspect", "--tls-verify=false", "docker://localhost:5000/signallayer-coreos:0.0.1"], stdout=target, check=True)
    with (run / "qemu.stdout").open("wb") as stdout, (run / "qemu.stderr").open("wb") as stderr:
        try:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=args.timeout)
            report["qemu_exit"] = result.returncode
        except subprocess.TimeoutExpired:
            report["qemu_exit"] = 124
    evidence = records(run / "evidence.tsv")
    (run / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    report["checks"] = evaluate(evidence)
    report["source_disk_unchanged"] = digest(disk) == report["disk_sha256"]
    report["result"] = "PASS" if report.get("qemu_exit") == 0 and report["source_disk_unchanged"] and all(report["checks"].values()) else "FAIL"
    (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
