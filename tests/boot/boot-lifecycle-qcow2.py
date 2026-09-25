#!/usr/bin/env python3
"""Prove Phase 3F offline rollback selection and activation under KVM."""

import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
UNIT = b"""[Unit]\nDescription=Disposable Phase 3F lifecycle probe\nDefaultDependencies=no\nConditionPathExists=!/etc/initrd-release\nAfter=multi-user.target NetworkManager.service\n[Service]\nType=simple\nImportCredential=phase3f-probe.sh\nExecStart=/usr/bin/bash %d/phase3f-probe.sh\nStandardOutput=journal+console\nStandardError=journal+console\nTimeoutStartSec=29min\n"""
DROPIN = b"[Unit]\nWants=phase3f-probe.service\n"


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
                "output": base64.b64decode(fields[2], validate=True).decode(
                    errors="replace"
                ),
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

    def identity(deployment):
        ostree = deployment["ostree"]
        return (
            f"{ostree['checksum']}.{ostree['deploySerial']}",
            deployment["image"]["imageDigest"],
        )

    checks = {}
    try:
        seed = parsed("seed_bootc")["status"]
        staged = parsed("staged_candidate_bootc")["status"]
        candidate = parsed("candidate_bootc")["status"]
        queued = parsed("queued_bootc")["status"]
        after = parsed("after_rollback_bootc")["status"]
        candidate_corectl = parsed("candidate_corectl")
        queued_corectl = parsed("queued_corectl")
        after_corectl = parsed("after_rollback_corectl")
        seed_corectl = parsed("seed_corectl")
        phase_a = identity(seed["booted"])
        phase_b = identity(staged["staged"])
        checks.update(
            {
                "fresh_a_has_no_pending_or_retained_deployment": seed["staged"] is None
                and seed["rollback"] is None
                and seed.get("rollbackQueued") is False,
                "fresh_a_corectl_states_are_idle": seed_corectl["update"]["state"]
                == "idle"
                and seed_corectl["update"]["reboot_required"] is False
                and seed_corectl["rollback"]["state"] == "idle"
                and seed_corectl["rollback"]["reboot_required"] is False,
                "candidate_staged_by_existing_update_path": identity(staged["booted"])
                == phase_a
                and phase_b != phase_a
                and staged["staged"]["downloadOnly"] is False,
                "candidate_activated_and_a_retained": identity(candidate["booted"])
                == phase_b
                and identity(candidate["rollback"]) == phase_a
                and candidate["staged"] is None
                and candidate.get("rollbackQueued") is False,
                "candidate_schema_0_2_idle_states": candidate_corectl["schema_version"]
                == "0.2"
                and candidate_corectl["update"]["state"] == "idle"
                and candidate_corectl["rollback"]["state"] == "idle",
                "rollback_queued_without_changing_deployments": identity(queued["booted"])
                == phase_b
                and identity(queued["rollback"]) == phase_a
                and queued["staged"] is None
                and queued.get("rollbackQueued") is True,
                "corectl_reports_queued_independent_state": queued_corectl["update"]["state"]
                == "idle"
                and queued_corectl["update"]["reboot_required"] is False
                and queued_corectl["rollback"]["state"] == "queued"
                and queued_corectl["rollback"]["reboot_required"] is True,
                "exact_a_booted_after_rollback": identity(after["booted"]) == phase_a,
                "b_retained_after_rollback": identity(after["rollback"]) == phase_b,
                "rollback_queue_cleared": after.get("rollbackQueued") is False
                and after["staged"] is None,
                "post_rollback_corectl_reports_a": after_corectl["booted"]["deployment_id"]
                == phase_a[0]
                and after_corectl["booted"]["image_digest"] == phase_a[1],
            }
        )
    except (KeyError, TypeError, ValueError):
        checks["machine_readable_lifecycle_evidence"] = False

    unit = text("rollback_unit")
    process = text("rollback_process")
    result = text("rollback_result")
    journal = text("rollback_journal").lower()
    update_unit = text("update_unit")
    update_process = text("update_process")
    checks.update(
        {
            "probe_completed": ok("complete") and text("complete") == "done",
            "existing_update_path_succeeded": ok("start_update")
            and ok("update_wait")
            and "Result=success" in text("update_result"),
            "fixed_update_command": "ExecStart=/usr/bin/bootc upgrade --quiet"
            in update_unit
            and "--apply" not in update_unit
            and "--download-only" not in update_unit
            and "/bin/sh" not in update_unit
            and "/bin/bash" not in update_unit,
            "update_unit_uses_fixed_mutation_label": "sl_update_unit_file_t:s0"
            in text("update_unit_label"),
            "update_worker_exact_install_domain": ok("update_process")
            and "system_u:system_r:install_t:s0" in update_process
            and "cmdline=/usr/bin/bootc upgrade --quiet " in update_process
            and "cgroup=0::/system.slice/sl-update.service" in update_process,
            "start_rollback_returned_promptly": ok("start_rollback")
            and int(text("start_rollback_elapsed_ns") or 3_000_000_000)
            < 3_000_000_000,
            "fixed_rollback_command": "ExecStart=/usr/bin/bootc rollback" in unit
            and "--apply" not in unit
            and "--soft-reboot" not in unit
            and "/bin/sh" not in unit
            and "/bin/bash" not in unit,
            "dedicated_unit_label": "sl_update_unit_file_t:s0"
            in text("rollback_unit_label"),
            "worker_exact_install_domain": ok("rollback_process")
            and "system_u:system_r:install_t:s0" in process
            and "cmdline=/usr/bin/bootc rollback " in process
            and "cgroup=0::/system.slice/sl-rollback.service" in process,
            "rollback_worker_succeeded": ok("rollback_wait")
            and "Result=success" in result
            and "ExecMainStatus=0" in result,
            "registry_unavailable_for_rollback": ok("registry_listener")
            and not text("registry_listener")
            and not ok("registry_unavailable")
            and not ok("registry_still_unavailable"),
            "rollback_did_not_download": not any(
                word in journal
                for word in ("downloading", "fetching image", "pulling image")
            ),
            "one_activation_and_one_rollback_reboot": text(
                "activation_reboot_requested"
            )
            == text("rollback_reboot_requested")
            == "systemctl reboot",
            "boot_ids_match_lifecycle": text("boot_id_seed")
            == text("boot_id_staged")
            and text("boot_id_seed") != text("boot_id_candidate")
            and text("boot_id_candidate") == text("boot_id_queued")
            and text("boot_id_after_rollback") != text("boot_id_queued"),
            "clean_shutdown": text("clean_shutdown_requested")
            == "systemctl poweroff",
            "selinux_enforcing_all_boots": all(
                text(f"selinux_{suffix}") == "Enforcing"
                for suffix in ("seed", "candidate", "queued", "after_rollback")
            ),
            "no_unexpected_relevant_avcs": all(
                expected_platform_avcs(key)
                for key in ("avcs_seed", "avcs_candidate", "avcs_after_rollback")
            ),
            "systemd_healthy_all_boots": all(
                text(f"target_{suffix}") == "active"
                and text(f"system_state_{suffix}") == "running"
                and not text(f"failed_{suffix}")
                and text(f"platform_service_{suffix}") == "active"
                for suffix in ("seed", "candidate", "queued", "after_rollback")
            ),
            "network_healthy_all_boots": all(
                text(f"network_manager_{suffix}") == "active"
                and bool(text(f"address_{suffix}"))
                and bool(text(f"route_{suffix}"))
                for suffix in ("seed", "candidate", "queued", "after_rollback")
            ),
            "immutable_writes_rejected_all_boots": all(
                not ok(f"{kind}_write_{suffix}")
                and "Read-only file system" in text(f"{kind}_write_{suffix}")
                for suffix in ("seed", "candidate", "queued", "after_rollback")
                for kind in ("root", "usr")
            ),
        }
    )
    for suffix in ("seed", "candidate", "queued", "after_rollback"):
        try:
            mounts = parsed(f"mounts_{suffix}")["filesystems"]
            flat = {}

            def visit(items):
                for item in items:
                    flat[item["target"]] = item
                    visit(item.get("children", []))

            visit(mounts)
            checks[f"immutable_mounts_{suffix}"] = flat["/"]["fstype"] == "overlay" and all(
                "ro" in flat[path]["options"].split(",")
                for path in ("/", "/sysroot")
            )
        except (KeyError, TypeError, ValueError):
            checks[f"immutable_mounts_{suffix}"] = False
    return checks


def credential(name, value):
    return (
        "type=11,value=io.systemd.credential.binary:"
        + name
        + "="
        + base64.b64encode(value).decode()
    )


def qemu_command(ovmf_code, variables, overlay, run, probe, cpus=4):
    return [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-smp",
        str(cpus),
        "-m",
        "4096",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={variables}",
        "-drive",
        f"if=none,id=os,format=qcow2,file={overlay}",
        "-device",
        "virtio-blk-pci,drive=os",
        "-nic",
        "user,model=virtio-net-pci,mac=52:54:00:00:03:0e",
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
        "virtserialport,chardev=evidence,name=org.signallayer.phase3f-test",
        "-smbios",
        credential("systemd.extra-unit.phase3f-probe.service", UNIT),
        "-smbios",
        credential("systemd.unit-dropin.multi-user.target", DROPIN),
        "-smbios",
        credential("phase3f-probe.sh", probe),
    ]


def runtime_identity_checks(evidence, expected_a_digest, expected_b_digest):
    checks = {}
    try:
        seed = json.loads(evidence["seed_bootc"]["output"])["status"]
        staged = json.loads(evidence["staged_candidate_bootc"]["output"])["status"]
        after = json.loads(evidence["after_rollback_bootc"]["output"])["status"]
        checks["runtime_a_matches_source_oci"] = (
            seed["booted"]["image"]["imageDigest"] == expected_a_digest
            and after["booted"]["image"]["imageDigest"] == expected_a_digest
        )
        checks["runtime_b_matches_registry_oci"] = (
            staged["staged"]["image"]["imageDigest"] == expected_b_digest
            and after["rollback"]["image"]["imageDigest"] == expected_b_digest
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        checks["runtime_expected_oci_identities"] = False
    return checks


def overall_result(report):
    return (
        "PASS"
        if report.get("qemu_exit") == 0
        and report["source_disk_unchanged"]
        and report["retained_overlay_exists"]
        and all(report["checks"].values())
        else "FAIL"
    )


# Release 0.0.2 mode (4E). The default 3F mode above is unchanged.
AGREEMENT_START = "    # Platform/Session1 agreement: status reads are not atomic, so boot-time\n"
AGREEMENT_END = '        collect post_agree_converged echo "$post_converged"\n    fi\n'
AGREEMENT_SUFFIXES = ("seed", "candidate", "after_rollback")
STATUS_SUFFIXES = ("seed", "candidate", "queued", "after_rollback")
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def load_boot_qcow2():
    spec = importlib.util.spec_from_file_location("boot_qcow2", HERE / "boot-qcow2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agreement_block(prefix):
    """4D's converged Platform/Session1/Platform read, reused verbatim from
    guest-reboot-post-probe.sh with only its record prefix changed."""
    source = (HERE / "guest-reboot-post-probe.sh").read_text()
    if source.count(AGREEMENT_START) != 1 or source.count(AGREEMENT_END) != 1:
        raise RuntimeError("4D agreement block markers are missing or ambiguous")
    start = source.index(AGREEMENT_START)
    end = source.index(AGREEMENT_END) + len(AGREEMENT_END)
    return source[start:end].replace("post_agree_", prefix)


def compose_release_0_0_2_probe(probe):
    replacements = (
        ('chmod 0700 "$state_dir"\n',
         'chmod 0700 "$state_dir"\n'
         'cat /proc/sys/kernel/random/boot_id >> "$state_dir/boot-sequence"\n'),
        ("    collect seed_corectl corectl status --json\n",
         "    collect seed_corectl corectl status --json\n" + agreement_block("seed_agree_")),
        ("    collect candidate_corectl corectl status --json\n",
         "    collect candidate_corectl corectl status --json\n" + agreement_block("candidate_agree_")),
        ("collect after_rollback_corectl corectl status --json\n",
         "collect after_rollback_corectl corectl status --json\n" + agreement_block("after_rollback_agree_")),
        # Both reboots use StartReboot. SIGTERM is ignored so corectl's exit
        # status can be recorded if the probe survives the start of shutdown.
        ("    record activation_reboot_requested 'systemctl reboot'\n    systemctl reboot\n",
         "    record activation_reboot_requested 'corectl reboot'\n    trap '' TERM\n"
         "    collect activation_reboot_corectl corectl reboot\n"),
        ("    record rollback_reboot_requested 'systemctl reboot'\n    systemctl reboot\n",
         "    record rollback_reboot_requested 'corectl reboot'\n    trap '' TERM\n"
         "    collect rollback_reboot_corectl corectl reboot\n"),
        ("record clean_shutdown_requested 'systemctl poweroff'\n",
         'collect boot_sequence cat "$state_dir/boot-sequence"\n'
         "record clean_shutdown_requested 'systemctl poweroff'\n"),
    )
    text = probe.decode()
    for old, new in replacements:
        if text.count(old) != 1:
            raise RuntimeError(f"0.0.2 probe anchor missing or ambiguous: {old.strip()}")
        text = text.replace(old, new)
    return text.encode()


def evaluate_release_0_0_2(evidence):
    """3F checks with 0.0.2 expectations; the 3F AVC allowlist is unchanged."""
    boot_qcow2 = load_boot_qcow2()

    def ok(key):
        return evidence.get(key, {}).get("exit_code") == 0

    def text(key):
        return evidence.get(key, {}).get("output", "").strip()

    checks = evaluate(evidence)
    checks.pop("candidate_schema_0_2_idle_states", None)
    try:
        statuses = {suffix: json.loads(text(f"{suffix}_corectl")) for suffix in STATUS_SUFFIXES}
        checks["release_0_0_2_status_all_boots"] = all(
            ok(f"{suffix}_corectl")
            and status["schema_version"] == "0.3"
            and status["platform_api_version"] == "0.2"
            for suffix, status in statuses.items()
        )
        candidate = statuses["candidate"]
        checks["candidate_schema_0_3_idle_states"] = (
            candidate["schema_version"] == "0.3"
            and candidate["update"]["state"] == "idle"
            and candidate["rollback"]["state"] == "idle"
        )
    except (KeyError, TypeError, ValueError):
        checks["release_0_0_2_status_all_boots"] = False
        checks["candidate_schema_0_3_idle_states"] = False
    checks["one_activation_and_one_rollback_reboot"] = (
        text("activation_reboot_requested")
        == text("rollback_reboot_requested")
        == "corectl reboot"
    )
    boot_ids = [text(f"boot_id_{suffix}") for suffix in ("seed", "candidate", "after_rollback")]
    sequence = text("boot_sequence").split()
    sequence_ok = (
        ok("boot_sequence")
        and sequence == boot_ids
        and len(set(boot_ids)) == 3
        and all(BOOT_ID.fullmatch(value) for value in boot_ids)
    )
    checks["boot_sequence_exactly_three_boots"] = sequence_ok
    details = {"boot_sequence": sequence, "reboots": {}, "session_agreement": {}}
    # 4D semantics: exit 0 or 3, or not captured, only if the boot sequence
    # proves exactly one reboot for each transition.
    for name in ("activation", "rollback"):
        recorded = evidence.get(f"{name}_reboot_corectl")
        checks[f"{name}_reboot_outcome_acceptable"] = sequence_ok and (
            recorded is None or recorded["exit_code"] in (0, 3)
        )
        details["reboots"][name] = boot_qcow2.corectl_reboot_outcome(recorded)
    for suffix in AGREEMENT_SUFFIXES:
        prefix = f"{suffix}_agree_"
        mapped = {
            "post_agree_" + key[len(prefix):]: value
            for key, value in evidence.items()
            if key.startswith(prefix)
        }
        checks[f"{suffix}_platform_session_agree"], details["session_agreement"][suffix] = (
            boot_qcow2.session_agreement(mapped)
        )
    return checks, details


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
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--expected-a-digest", required=True)
    parser.add_argument("--expected-b-digest", required=True)
    parser.add_argument("--cpus", type=int, default=4, help="Guest virtual CPU count (default: 4, as in 3F)")
    parser.add_argument(
        "--release-0-0-2",
        action="store_true",
        help="4E: schema 0.3, API 0.2, corectl reboot, and converged Platform/Session1 reads",
    )
    args = parser.parse_args()
    disk = args.disk.resolve(strict=True)
    output = pathlib.Path(__file__).resolve().parents[2] / "image/build/output"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    prefix = "phase4e-acceptance" if args.release_0_0_2 else "phase3f-acceptance"
    run = output / f"{prefix}-{stamp}"
    run.mkdir(parents=True)
    probe = pathlib.Path(__file__).with_name("guest-lifecycle-probe.sh").read_bytes()
    if args.release_0_0_2:
        probe = compose_release_0_0_2_probe(probe)
    (run / "probe.sh").write_bytes(probe)
    overlay = run / "complete-lifecycle.qcow2"
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

    command = qemu_command(
        args.ovmf_code.resolve(), variables, overlay, run, probe, args.cpus
    )
    (run / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
    report = {
        "phase": "4E" if args.release_0_0_2 else "3F",
        "result": "FAIL",
        "output": str(run),
        "disk": str(disk),
        "disk_sha256": digest(disk),
        "probe_sha256": hashlib.sha256(probe).hexdigest(),
        "qemu_version": subprocess.check_output(
            ["qemu-system-x86_64", "--version"], text=True
        ).splitlines()[0],
        "acceleration": "kvm",
        "firmware": {
            "code": str(args.ovmf_code.resolve()),
            "code_sha256": digest(args.ovmf_code.resolve()),
            "vars_template": str(args.ovmf_vars.resolve()),
            "vars_template_sha256": digest(args.ovmf_vars.resolve()),
        },
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
    if args.release_0_0_2:
        report["release"] = "0.0.2"
        report["checks"], report["release_0_0_2"] = evaluate_release_0_0_2(evidence)
    else:
        report["checks"] = evaluate(evidence)
    report["checks"].update(
        runtime_identity_checks(evidence, args.expected_a_digest, args.expected_b_digest)
    )
    report["source_disk_unchanged"] = digest(disk) == report["disk_sha256"]
    report["retained_overlay_exists"] = overlay.exists()
    report["result"] = overall_result(report)
    (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
