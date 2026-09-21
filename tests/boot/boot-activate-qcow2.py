#!/usr/bin/env python3
"""Prove a Phase 3C staged deployment activates after one graceful reboot."""

import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess


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
            found[fields[0]] = {
                "exit_code": int(fields[1]),
                "output": base64.b64decode(fields[2], validate=True).decode(errors="replace"),
            }
        except (ValueError, UnicodeError):
            pass
    return found


def evaluate(evidence):
    def ok(key):
        return evidence.get(key, {}).get("exit_code") == 0

    def text(key):
        return evidence.get(key, {}).get("output", "").strip()

    def parsed(key):
        return json.loads(text(key))

    def deployment_id(deployment):
        ostree = deployment["ostree"]
        return f"{ostree['checksum']}.{ostree['deploySerial']}"

    def expected_platform_avcs(key):
        return ok(key) and all(
            "denied  { write }" in line
            and 'comm="bootc"' in line
            and 'name="objects"' in line
            and "scontext=system_u:system_r:sl_platformd_t:s0" in line
            and "tclass=dir" in line
            and "permissive=0" in line
            for line in text(key).splitlines()
        )

    checks = {}
    try:
        initial = parsed("initial_bootc")["status"]
        before = parsed("before_reboot_bootc")["status"]
        after = parsed("after_reboot_bootc")["status"]
        initial_corectl = parsed("initial_corectl")
        before_corectl = parsed("before_reboot_corectl")
        after_corectl = parsed("after_reboot_corectl")
        a = initial["booted"]
        b = before["staged"]
        rollback = after["rollback"]
        checks.update(
            {
                "initial_a_has_no_staged_deployment": initial["staged"] is None,
                "initial_corectl_is_idle": initial_corectl["update"]["state"] == "idle"
                and initial_corectl["update"]["reboot_required"] is False,
                "a_remains_booted_before_reboot": before["booted"]["ostree"] == a["ostree"]
                and before["booted"]["image"]["imageDigest"]
                == a["image"]["imageDigest"],
                "b_is_distinct_and_staged": b is not None
                and b["ostree"] != a["ostree"]
                and b["image"]["imageDigest"] != a["image"]["imageDigest"],
                "b_is_not_download_only": b["downloadOnly"] is False,
                "corectl_requires_reboot": before_corectl["update"]["state"] == "staged"
                and before_corectl["update"]["reboot_required"] is True
                and before_corectl["update"]["staged"]["deployment_id"]
                == deployment_id(b),
                "exact_b_became_booted": after["booted"]["ostree"] == b["ostree"]
                and after["booted"]["image"]["imageDigest"]
                == b["image"]["imageDigest"],
                "b_is_no_longer_staged": after["staged"] is None,
                "reboot_requirement_cleared": after_corectl["update"]["state"] == "idle"
                and after_corectl["update"]["reboot_required"] is False
                and after_corectl["update"]["staged"] is None,
                "corectl_reports_b_booted": after_corectl["booted"]["deployment_id"]
                == deployment_id(b)
                and after_corectl["booted"]["image_digest"]
                == b["image"]["imageDigest"],
                "a_is_retained_for_rollback": rollback is not None
                and rollback["ostree"] == a["ostree"]
                and rollback["image"]["imageDigest"] == a["image"]["imageDigest"]
                and after_corectl["retained_rollback"]["deployment_id"]
                == deployment_id(a),
            }
        )
    except (KeyError, TypeError, ValueError):
        checks["machine_readable_lifecycle_evidence"] = False

    unit = text("update_unit")
    process = text("worker_process")
    result = text("worker_result")
    checks.update(
        {
            "probe_completed_after_reboot": ok("complete"),
            "start_update_prompt": ok("start_update")
            and int(text("start_update_elapsed_ns") or 3_000_000_000) < 3_000_000_000,
            "concurrent_request_busy": not ok("concurrent_update")
            and parsed("concurrent_update")["error"]["code"] == "Busy",
            "fixed_update_command": "ExecStart=/usr/bin/bootc upgrade --quiet" in unit
            and "--apply" not in unit
            and "--download-only" not in unit
            and "/bin/sh" not in unit
            and "/bin/bash" not in unit,
            "worker_uses_install_domain": ok("worker_process")
            and "system_u:system_r:install_t:s0" in process,
            "worker_exact_process": "cmdline=/usr/bin/bootc upgrade --quiet " in process
            and "cgroup=0::/system.slice/sl-update.service" in process,
            "worker_succeeded": ok("worker_wait")
            and "Result=success" in result
            and "ExecMainStatus=0" in result,
            "dedicated_runtime_labels": "sl_bootc_runtime_t:s0"
            in text("runtime_context")
            and "sl_bootc_state_t:s0" in text("staged_marker_context"),
            "one_graceful_reboot_requested": ok("reboot_requested")
            and text("reboot_requested") == "systemctl reboot",
            "boot_id_changed_once": text("boot_id_initial")
            == text("boot_id_before_reboot")
            and text("boot_id_after_reboot") != text("boot_id_before_reboot"),
            "staged_marker_consumed": ok("staged_marker_absent_after_reboot"),
            "platform_service_healthy_on_b": text("platform_service_after") == "active",
            "systemd_healthy_before_and_after": text("target_initial")
            == text("target_after")
            == "active"
            and text("system_state_initial") == text("system_state_after") == "running"
            and not text("failed_initial")
            and not text("failed_after"),
            "network_healthy_before_and_after": text("network_manager_initial")
            == text("network_manager_after")
            == "active"
            and bool(text("address_initial"))
            and bool(text("address_after"))
            and bool(text("route_initial"))
            and bool(text("route_after")),
            "selinux_enforcing_before_and_after": text("selinux_initial")
            == text("selinux_after")
            == "Enforcing",
            "no_unexpected_relevant_avcs": expected_platform_avcs("relevant_avcs_before")
            and expected_platform_avcs("relevant_avcs_after"),
            "immutable_writes_rejected": all(
                not ok(key) and "Read-only file system" in text(key)
                for key in (
                    "root_write_initial",
                    "usr_write_initial",
                    "root_write_after",
                    "usr_write_after",
                )
            ),
        }
    )
    for suffix in ("initial", "after"):
        try:
            mounts = json.loads(text(f"mounts_{suffix}"))["filesystems"]
            flat = {}

            def visit(items):
                for item in items:
                    flat[item["target"]] = item
                    visit(item.get("children", []))

            visit(mounts)
            checks[f"immutable_mounts_{suffix}"] = (
                flat["/"]["fstype"] == "overlay"
                and all(
                    "ro" in flat[path]["options"].split(",")
                    for path in ("/", "/sysroot")
                )
            )
        except (KeyError, TypeError, ValueError):
            checks[f"immutable_mounts_{suffix}"] = False
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disk", type=pathlib.Path)
    parser.add_argument(
        "--ovmf-code",
        type=pathlib.Path,
        default=pathlib.Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"),
    )
    parser.add_argument(
        "--ovmf-vars",
        type=pathlib.Path,
        default=pathlib.Path("/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    )
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    disk = args.disk.resolve(strict=True)
    output = pathlib.Path(__file__).resolve().parents[2] / "image/build/output"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = output / f"phase3d-acceptance-{stamp}"
    run.mkdir(parents=True)
    probe = pathlib.Path(__file__).with_name("guest-activation-probe.sh").read_bytes()
    (run / "probe.sh").write_bytes(probe)
    unit = b"""[Unit]\nDescription=Disposable Phase 3D activation probe\nDefaultDependencies=no\nConditionPathExists=!/etc/initrd-release\nAfter=multi-user.target NetworkManager.service\n[Service]\nType=simple\nImportCredential=phase3d-probe.sh\nExecStart=/usr/bin/bash %d/phase3d-probe.sh\nStandardOutput=journal+console\nStandardError=journal+console\nTimeoutStartSec=19min\n"""
    dropin = b"[Unit]\nWants=phase3d-probe.service\n"
    overlay = run / "b-active-a-retained.qcow2"
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(disk),
            str(overlay),
        ],
        check=True,
    )
    variables = run / "OVMF_VARS.fd"
    shutil.copyfile(args.ovmf_vars, variables)

    def credential(name, value):
        return (
            "type=11,value=io.systemd.credential.binary:"
            + name
            + "="
            + base64.b64encode(value).decode()
        )

    command = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        "4",
        "-m",
        "4096",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={args.ovmf_code.resolve()}",
        "-drive",
        f"if=pflash,format=raw,file={variables}",
        "-drive",
        f"if=none,id=os,format=qcow2,file={overlay}",
        "-device",
        "virtio-blk-pci,drive=os",
        "-nic",
        "user,model=virtio-net-pci,mac=52:54:00:00:03:0d",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        f"file:{run / 'serial.log'}",
        "-device",
        "virtio-serial-pci",
        "-chardev",
        f"file,id=evidence,path={run / 'evidence.tsv'}",
        "-device",
        "virtserialport,chardev=evidence,name=org.signallayer.phase3d-test",
        "-smbios",
        credential("systemd.extra-unit.phase3d-probe.service", unit),
        "-smbios",
        credential("systemd.unit-dropin.multi-user.target", dropin),
        "-smbios",
        credential("phase3d-probe.sh", probe),
    ]
    (run / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
    report = {
        "phase": "3D",
        "result": "FAIL",
        "output": str(run),
        "disk": str(disk),
        "disk_sha256": digest(disk),
        "probe_sha256": hashlib.sha256(probe).hexdigest(),
        "qemu_version": subprocess.check_output(
            ["qemu-system-x86_64", "--version"], text=True
        ).splitlines()[0],
        "retained_overlay": str(overlay),
    }
    with (run / "registry-target.json").open("wb") as target:
        subprocess.run(
            [
                "skopeo",
                "inspect",
                "--tls-verify=false",
                "docker://localhost:5000/signallayer-coreos:0.0.1",
            ],
            stdout=target,
            check=True,
        )
    with (run / "qemu.stdout").open("wb") as stdout, (
        run / "qemu.stderr"
    ).open("wb") as stderr:
        try:
            result = subprocess.run(
                command, stdout=stdout, stderr=stderr, timeout=args.timeout
            )
            report["qemu_exit"] = result.returncode
        except subprocess.TimeoutExpired:
            report["qemu_exit"] = 124
    evidence = records(run / "evidence.tsv")
    (run / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    )
    report["checks"] = evaluate(evidence)
    report["source_disk_unchanged"] = digest(disk) == report["disk_sha256"]
    report["retained_overlay_exists"] = overlay.exists()
    report["result"] = (
        "PASS"
        if report.get("qemu_exit") == 0
        and report["source_disk_unchanged"]
        and report["retained_overlay_exists"]
        and all(report["checks"].values())
        else "FAIL"
    )
    (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
