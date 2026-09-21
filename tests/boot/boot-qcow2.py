#!/usr/bin/env python3
"""Bounded UEFI disk boot on native Linux, with serial and guest evidence."""
import argparse
import base64
import configparser
import gzip
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
import xml.etree.ElementTree as ET
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


def repository_writability_denials(evidence):
    """Recognize a denied access query, never a mutation or unmatched AVC."""
    import re
    observation = evidence.get("security_repo_objects", {})
    if observation.get("exit_code") != 0:
        return set()
    try:
        objects = json.loads(observation["output"])
    except (ValueError, KeyError):
        return set()
    if (objects.get("path") != "/sysroot/ostree/repo/objects" or
            objects.get("context") != "unconfined_u:object_r:system_conf_t:s0" or
            not isinstance(objects.get("inode"), int) or objects["inode"] <= 0 or
            objects.get("device") != "vda3"):
        return set()

    def field(body, name):
        match = re.search(r"\b" + name + r'=(?:"([^"]*)"|(\S+))', body)
        return (match[1] if match[1] is not None else match[2]) if match else None

    journal = evidence.get("security_audit_json", {})
    if journal.get("exit_code") != 0:
        return set()
    events = {}
    try:
        for line in journal["output"].splitlines():
            entry = json.loads(line)
            kind = entry.get("_AUDIT_TYPE")
            if kind not in ("1400", "1300", "1327"):
                continue
            if (entry.get("_TRANSPORT") != "audit" or
                    not re.fullmatch(r"[0-9a-f]{32}", entry.get("_BOOT_ID", "")) or
                    not re.fullmatch(r"[0-9]+", entry.get("_AUDIT_ID", ""))):
                return set()
            event = events.setdefault((entry["_BOOT_ID"], entry["_AUDIT_ID"]), {})
            event.setdefault(kind, []).append(entry["MESSAGE"])
    except (ValueError, KeyError, TypeError):
        return set()
    expected = set()
    for event in events.values():
        if any(len(event.get(kind, [])) != 1 for kind in ("1400", "1300", "1327")):
            continue
        avc, syscall, title = (event[k][0] for k in ("1400", "1300", "1327"))
        avc = avc[avc.index("avc:"):] if "avc:" in avc else ""
        pid = field(avc, "pid")
        if not pid or not pid.isdigit():
            continue
        avc_fields = {"comm": "bootc", "name": "objects", "dev": objects["device"],
                      "ino": str(objects["inode"]), "scontext": "system_u:system_r:sl_platformd_t:s0",
                      "tcontext": objects["context"], "tclass": "dir", "permissive": "0"}
        syscall_fields = {"arch": "c000003e", "syscall": "439", "success": "no", "exit": "-13",
                          "a2": "2", "a3": "0", "comm": "bootc", "pid": pid,
                          "subj": "system_u:system_r:sl_platformd_t:s0"}
        if (re.search(r"^avc:\s+denied\s+\{\s*write\s*\}", avc) and
                all(field(avc, k) == v for k, v in avc_fields.items()) and
                all(field(syscall, k) == v for k, v in syscall_fields.items()) and
                (field(title, "proctitle") or "").lower() == "626f6f746300737461747573002d2d6a736f6e"):
            expected.add(" ".join(avc.split()))
    return expected


def evaluate_hardening(evidence):
    def text(key):
        return evidence.get(key, {}).get("output", "").strip()

    def ok(key):
        return evidence.get(key, {}).get("exit_code") == 0

    def domain(key):
        return ok(key) and "system_u:system_r:sl_platformd_t:s0" in text(key)

    def request_matches(response, scenario):
        request = response["request"]
        expected = {"destination": "org.signallayer.Platform1", "path": "/org/signallayer/Platform1",
                    "interface": "org.signallayer.Platform1", "member": "GetStatus", "signature": "", "body": []}
        if scenario == "own":
            expected.update(destination="org.freedesktop.DBus", path="/org/freedesktop/DBus", interface="org.freedesktop.DBus", member="RequestName", signature="su", body=["org.signallayer.Platform1", 4])
        elif scenario == "unsupported":
            expected["member"] = "UnsupportedPhase3BMethod"
        elif scenario == "wrong-path":
            expected["path"] = "/org/signallayer/WrongObject"
        elif scenario == "wrong-interface":
            expected["interface"] = "org.signallayer.WrongInterface"
        elif scenario == "invalid-signature":
            expected.update(signature="s", body=["unexpected"])
        return request["scenario"] == scenario and all(request.get(key) == value for key, value in expected.items())

    checks = {}
    try:
        try:
            primary = json.loads(text("platform_json")) if ok("platform_json") else None
        except (ValueError, TypeError):
            primary = None
        checks["security_phase3a_reference_status"] = bool(
            isinstance(primary, dict) and primary.get("schema_version") == "0.1" and
            "error" not in primary
        )
        # Preserve granular hardening diagnostics if a retained Phase 3A
        # observation fails. Its own check still fails acceptance; the clean
        # first-boot observation is only a diagnostic comparison reference.
        expected = primary if checks["security_phase3a_reference_status"] else json.loads(
            text("security_first_status")
        )
        if expected.get("schema_version") != "0.1" or "error" in expected:
            raise ValueError("No successful platform observation is available")
        for key in ("security_initial_json", "security_after_bus_json", "security_timeout_recovery",
                    "security_restart_inflight_recovery", "security_restart_1_json", "security_restart_2_json",
                    "security_cli_deadline_recovery", "security_final_json", "security_final_unprivileged_json"):
            checks[key + "_matches"] = ok(key) and json.loads(text(key)) == expected
        checks["security_first_status_without_root_preparation"] = ok("security_first_status") and json.loads(text("security_first_status")) == expected
        automatic = dict(line.split("=", 1) for line in text("security_automatic_unit").splitlines())
        base_dropins = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
        checks["security_automatic_confined_owner"] = ok("security_automatic_unit") and automatic.get("ActiveState") == "active" and automatic.get("SubState") == "running" and automatic.get("DropInPaths") == base_dropins and domain("security_automatic_domain") and ok("security_automatic_owner") and text("security_automatic_owner") == "u " + automatic.get("MainPID", "")
        checks["security_confined_daemon_and_restarts"] = all(domain(key) for key in (
            "security_domain", "security_restart_inflight_domain", "security_restart_1_domain",
            "security_restart_2_domain", "security_negative_domain", "security_final_domain"))
        checks["security_image_owned_labels"] = ok("security_labels") and all(
            value in text("security_labels") for value in (
                "sl_platformd_exec_t:s0", "sl_platformd_release_t:s0"))
        checks["security_image_owned_lock_directory"] = ok("security_ostree_lock_directory") and "sl_platformd_ostree_t:s0" in text("security_ostree_lock_directory")
        crypto = json.loads(text("security_crypto_configuration"))
        checks["security_crypto_configuration_preserved"] = ok("security_crypto_configuration") and all(crypto.get(k) is True for k in ("configuration_preserved", "provider_preserved", "provider_set_preserved")) and crypto.get("configuration_mode") == 0o644 and crypto.get("provider_mode") == 0o644
        bus_config = ET.fromstring(text("security_bus_config"))
        associations = bus_config.findall("selinux/associate")
        checks["security_image_owned_bus_association"] = ok("security_bus_config") and len(associations) == 1 and associations[0].attrib == {"own":"org.signallayer.Platform1", "context":"system_u:system_r:sl_platformd_t:s0"}
        checks["security_module_loaded"] = ok("security_modules") and any(
            "sl_platformd" in line.split() for line in text("security_modules").splitlines())
        unit = dict(line.split("=", 1) for line in text("security_unit").splitlines())
        checks["security_sandbox_preserved"] = ok("security_unit") and all(unit.get(key) == value for key, value in {
            "User":"root", "NoNewPrivileges":"yes", "PrivateTmp":"yes", "ProtectSystem":"strict",
            "ProtectHome":"yes", "ProtectKernelTunables":"yes", "ProtectControlGroups":"yes",
            "RestrictSUIDSGID":"yes", "FragmentPath":"/usr/lib/systemd/system/sl-platformd.service",
            "DropInPaths":base_dropins}.items()) and set(unit.get("CapabilityBoundingSet", "").split()) == {"cap_sys_admin", "cap_sys_ptrace"} and "/usr/bin/sl-platformd" in unit.get("ExecStart", "")
        daemon_status = dict(line.split(":", 1) for line in text("security_daemon_status").splitlines() if ":" in line)
        checks["security_actual_process_privileges"] = ok("security_daemon_status") and all(int(daemon_status.get(key, "0"), 16) == (1 << 19 | 1 << 21) for key in ("CapEff", "CapPrm", "CapBnd")) and daemon_status.get("NoNewPrivs", "").strip() == "1" and daemon_status.get("Uid", "").split() == ["0"] * 4 and daemon_status.get("Gid", "").split() == ["0"] * 4 and ok("security_daemon_executable") and text("security_daemon_executable") == "/usr/bin/sl-platformd"
        checks["security_name_free"] = ok("security_name_stop") and ok("security_name_free") and text("security_name_free") == "b false"
        cases = {"security_name_denied": "own", "security_unsupported":"unsupported",
                 "security_wrong-path":"wrong-path", "security_wrong-interface":"wrong-interface",
                 "security_invalid-signature":"invalid-signature", "security_status":"status"}
        for key, scenario in cases.items():
            response = json.loads(text(key))
            metadata = [json.loads(line) for line in text(key + "_metadata").splitlines()]
            uid = response["request"]["uid"]
            exact_request = request_matches(response, scenario)
            proven = exact_request and uid != 0 and response["request"]["sender"].startswith(":") and response["request"]["scenario"] == scenario and bool(metadata) and all(
                int(line["_UID"]) == uid and line["_SYSTEMD_UNIT"] == "slprobe-" + scenario + ".service" and line["_COMM"] == "python3" for line in metadata)
            if scenario == "status":
                checks[key] = proven and ok(key + "_start") and response["result"] == "success" and response["reply_signature"] == "s"
            else:
                allowed_errors = {"org.freedesktop.DBus.Error.AccessDenied"}
                if scenario == "invalid-signature":
                    allowed_errors.add("org.freedesktop.DBus.Error.InvalidArgs")
                checks[key] = proven and not ok(key + "_start") and response["result"] == "method_error" and response["error_name"] in allowed_errors
        for scenario in ("unsupported", "wrong-path", "wrong-interface", "invalid-signature"):
            value = json.loads(text("security_root_" + scenario))
            # The installed XML policy deliberately admits only the exact
            # public method shape, including for root. Retain whether the
            # broker rejected routing or the application rejected dispatch;
            # either is a precise, non-mutating outcome for these probes.
            errors = {"unsupported": {"org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.UnknownMethod"},
                      "wrong-path": {"org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.UnknownMethod"},
                      "wrong-interface": {"org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.UnknownInterface", "org.freedesktop.DBus.Error.UnknownMethod"},
                      "invalid-signature": {"org.freedesktop.DBus.Error.InvalidArgs"}}
            checks["security_dispatch_" + scenario] = not ok("security_root_" + scenario) and request_matches(value, scenario) and value["request"]["uid"] == 0 and value["result"] == "method_error" and value["error_name"] in errors[scenario]
        initial_backend = json.loads(text("bootc_status"))
        checks["security_deployment_unchanged"] = all(ok(key) and json.loads(text(key)) == initial_backend for key in ("security_after_bus_backend", "security_final_backend"))
        for key, error in (("security_busy", "Busy"), ("security_timeout_result", "BackendTimeout"), ("security_negative_json", "MetadataUnavailable")):
            value = json.loads(text(key))
            checks[key] = evidence[key]["exit_code"] == 1 and value["error"]["code"] == error and bool(value["error"]["message"])
        interrupted = json.loads(text("security_restart_inflight_result"))
        checks["security_interrupted_call_structured"] = evidence["security_restart_inflight_result"]["exit_code"] == 1 and interrupted["error"]["code"] == "ServiceUnavailable" and bool(interrupted["error"]["message"])
        checks["security_backend_deadline"] = ok("security_timeout_elapsed") and 14 <= float(text("security_timeout_elapsed")) < 25
        cli_deadline = json.loads(text("security_cli_deadline_result"))
        checks["security_cli_method_deadline"] = all(ok(key) for key in ("security_cli_deadline_stop", "security_cli_deadline_continue", "security_cli_deadline_elapsed")) and evidence["security_cli_deadline_result"]["exit_code"] == 1 and cli_deadline["error"]["code"] == "ServiceUnavailable" and 24 <= float(text("security_cli_deadline_elapsed")) < 35
        for key in ("security_timeout", "security_restart_inflight"):
            pid = text(key + "_held_pid")
            status = dict(line.split(":", 1) for line in text(key + "_held_status").splitlines() if ":" in line)
            checks[key + "_actual_confined_backend"] = pid.isdigit() and domain(key + "_held_domain") and status.get("Name", "").strip() == "bootc" and status.get("State", "").strip().startswith("T") and int(status.get("CapEff", "0"), 16) == (1 << 19 | 1 << 21) and text(key + "_held_command") == "/usr/bin/bootc status --json" and text(key + "_children").split() == [pid]
            checks[key + "_reaped"] = ok(key + "_child_reaped")
            environment = dict(line.split("=", 1) for line in text(key + "_held_crypto_config").splitlines())
            checks[key + "_fixed_crypto_configuration"] = ok(key + "_held_crypto_config") and environment.get("OPENSSL_CONF") == "/usr/lib/signallayer/openssl.cnf"
            checks[key + "_fixed_runtime_environment"] = ok(key + "_held_crypto_config") and environment == {
                "OPENSSL_CONF": "/usr/lib/signallayer/openssl.cnf", "SYSTEMD_BYPASS_USERDB": "1",
                "LIBMOUNT_UTAB": "/tmp/sl-platformd-utab"}
        checks["security_one_backend_after_busy"] = ok("security_timeout_children_after_busy") and text("security_timeout_children_after_busy").split() == [text("security_timeout_held_pid")]
        rejected = json.loads(text("security_invalid-signature"))
        rejection_metadata = [json.loads(line) for line in text("security_invalid-signature_metadata").splitlines()]
        checks["security_invalid_signature_does_not_observe"] = not ok("security_invalid-signature_start") and request_matches(rejected, "invalid-signature") and rejected["request"]["uid"] != 0 and rejected["request"]["signature"] == "s" and rejected["result"] == "method_error" and rejected["error_name"] == "org.freedesktop.DBus.Error.InvalidArgs" and bool(rejection_metadata) and all(int(line["_UID"]) == rejected["request"]["uid"] and line["_COMM"] == "python3" and line["_SYSTEMD_UNIT"] == "slprobe-invalid-signature.service" for line in rejection_metadata) and ok("security_invalid_signature_monitor_ready") and ok("security_invalid_signature_monitor_stop") and ok("security_invalid_signature_backend_children") and not text("security_invalid_signature_backend_children")
        checks["security_restarts_restored"] = all(ok(key) for key in ("security_name_restart", "security_restart_inflight_restart", "security_restart_1", "security_restart_2", "security_negative_reload", "security_negative_restart", "security_restore_reload", "security_restore_restart", "security_final_active")) and text("security_final_active") == "active" and ("DropInPaths=" + base_dropins + "\n") in evidence["security_final_unit"]["output"]
        checks["security_no_backend_leaks"] = ok("security_final_children") and not text("security_final_children") and not text("security_final_backend_processes")
        checks["security_final_running_no_failed"] = ok("security_final_system_state") and text("security_final_system_state") == "running" and ok("security_final_failed_units") and not text("security_final_failed_units")
        final_unit = dict(line.split("=", 1) for line in text("security_final_unit").splitlines())
        processes = text("security_final_confined_processes").splitlines()
        checks["security_only_final_confined_daemon"] = ok("security_final_confined_processes") and len(processes) == 1 and processes[0].split()[0] == final_unit.get("MainPID") and processes[0].split()[2:] == ["system_u:system_r:sl_platformd_t:s0", "/usr/bin/sl-platformd"]
        checks["security_transient_fixtures_removed"] = all(ok(key) for key in ("security_fixture_cleanup", "security_fixture_absent"))
        final_messages = [json.loads(line) for line in text("security_final_unprivileged_metadata").splitlines()]
        checks["security_final_unprivileged_proven"] = ok("security_final_unprivileged_start") and bool(final_messages) and all(int(line["_UID"]) != 0 and line["_COMM"] == "corectl" and line["_SYSTEMD_UNIT"] == "slprobe-hardening-final.service" for line in final_messages)
        checks["security_final_enforcing"] = ok("security_final_selinux") and text("security_final_selinux") == "Enforcing"
        after = dict(evidence)
        for old, new in (("mounts", "security_final_mounts"), ("root_write", "security_final_root_write"), ("usr_write", "security_final_usr_write")):
            after[old] = evidence.get(new, {})
        immutable = evaluate(after, "unused", "unused")
        for key in ("runtime_composefs", "root_and_sysroot_readonly", "root_rejects_writes", "usr_rejects_writes"):
            checks["security_after_" + key] = immutable[key]
        # Audit can be delivered both to the journal and auditd; retain all
        # sources, deduplicate exact lines and reject every unexpected daemon
        # or backend denial, including a failed entry-point transition.
        import re
        audit = "\n".join(text(key) for key in ("security_audit_journal", "security_audit_file", "security_kernel_journal"))
        relevant = set(line for line in audit.splitlines() if re.search(r"avc:\s+denied", line, re.I) and "sl_platformd_t" in line)
        negative_pid = text("security_negative_pid")
        metadata_denials = set(line for line in relevant if re.search(r"\bpid=" + re.escape(negative_pid) + r"\b", line) and "scontext=system_u:system_r:sl_platformd_t:s0" in line and "tcontext=system_u:object_r:shadow_t:s0" in line and "tclass=file" in line and re.search(r"\{[^}]*\bread\b", line) and "permissive=0" in line)
        def ownership_denial(line):
            return re.search(r"avc:\s+denied\s+\{\s*acquire_svc\s*\}", line, re.I) and "scontext=system_u:system_r:unconfined_service_t:s0" in line and "tcontext=system_u:system_r:sl_platformd_t:s0" in line and "tclass=dbus" in line and "permissive=0" in line and 'exe="/usr/bin/dbus-broker"' in line
        # USER_AVC identifies the broker PID, not the requesting client's PID.
        # Match its PID from the exclusive free-name negative-test window;
        # the raw request and journal metadata separately prove the client UID.
        broker_pids = set(re.search(r"\bpid=(\d+)\b", line).group(1) for line in text("security_name_denied_audit_journal").splitlines() if ownership_denial(line) and re.search(r"\bpid=(\d+)\b", line))
        ownership_denials = set(line for line in relevant if ownership_denial(line) and any(re.search(r"\bpid=" + pid + r"\b", line) for pid in broker_pids)) if checks.get("security_name_denied") and checks.get("security_name_free") and ok("security_name_denied_audit_journal") else set()
        checks["security_negative_matching_avc"] = bool(metadata_denials) and ok("security_negative_label") and "shadow_t:s0" in text("security_negative_fixture") and "-rw-r--r--" in text("security_negative_fixture")
        checks["security_name_denial_matching_avc"] = bool(ownership_denials)
        expected_probes = repository_writability_denials(evidence)
        probe_denials = set(line for line in relevant if "avc:" in line and " ".join(line[line.index("avc:"):].split()) in expected_probes)
        checks["security_readonly_repo_probe_correlated"] = bool(expected_probes) and bool(probe_denials)
        checks["security_no_unexpected_daemon_avcs"] = bool(metadata_denials) and bool(ownership_denials) and relevant == metadata_denials | ownership_denials | probe_denials
        checks["security_no_daemon_panics"] = ok("security_final_journal") and not any(word in text("security_final_journal").lower() for word in ("panicked at", "core dumped", "segmentation fault"))
    except (ValueError, KeyError, TypeError, ET.ParseError):
        checks["security_evidence_valid"] = False
    return checks


def inspect_loaded_policy(evidence, run, tools_image):
    value = evidence.get("security_loaded_policy", {})
    if value.get("exit_code") != 0:
        return {"security_loaded_policy_analyzed": False}
    binary = gzip.decompress(base64.b64decode(value["output"], validate=True))
    if len(binary) > 32 * 1024 * 1024:
        raise RuntimeError("Unexpectedly large guest policy")
    policy = run / "loaded-policy.bin"
    policy.write_bytes(binary)
    queries = {
        "domain": ["seinfo", "-t", "sl_platformd_t", "-x", "/policy"],
        "permissive": ["seinfo", "--permissive", "-x", "/policy"],
        "entry_transition": ["sesearch", "-T", "-s", "init_t", "-t", "sl_platformd_exec_t", "-c", "process", "/policy"],
        "child_transitions": ["sesearch", "-T", "-s", "sl_platformd_t", "-c", "process", "/policy"],
        "service_acquire": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "sl_platformd_t", "-c", "dbus", "-p", "acquire_svc", "/policy"],
        "default_service_acquire": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "system_dbusd_t", "-c", "dbus", "-p", "acquire_svc", "/policy"],
        "pid1_namespace_read": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "init_t", "-c", "file", "-p", "read", "/policy"],
        "pid1_ptrace": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "init_t", "-c", "process", "-p", "ptrace", "/policy"],
        "negative_read": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "shadow_t", "-c", "file", "-p", "read", "/policy"],
        "raw_disk_read": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "fixed_disk_device_t", "-c", "blk_file", "-p", "read", "/policy"],
        "generic_crypto_read": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "cert_t", "-c", "file", "-p", "read", "/policy"],
        "generic_usr_directory_write": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "usr_t", "-c", "dir", "-p", "write", "/policy"],
        "generic_configuration_directory_write": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "system_conf_t", "-c", "dir", "-p", "write", "/policy"],
        "lock_transition": ["sesearch", "-T", "-s", "sl_platformd_t", "-t", "sl_platformd_ostree_t", "-c", "file", "/policy"],
        "lock_parent_file_create": ["sesearch", "-A", "-s", "sl_platformd_t", "-t", "sl_platformd_ostree_t", "-c", "file", "-p", "create", "/policy"],
        "domain_allows": ["sesearch", "-A", "-s", "sl_platformd_t", "/policy"],
    }
    analysis = {}
    for name, query in queries.items():
        command = ["podman", "run", "--rm", "--network=none", "--volume", str(policy) + ":/policy:ro,Z", tools_image] + query
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        analysis[name] = {"command": command, "exit_code": result.returncode, "output": result.stdout, "stderr": result.stderr}
    # Analyze every permitted process-transition target, not just familiar
    # names: an indirectly unconfined target would also violate the boundary.
    import re
    targets = set(re.findall(r"type_transition \S+ \S+:process (\S+);", analysis["child_transitions"]["output"]))
    for target in sorted(targets):
        command = ["podman", "run", "--rm", "--network=none", "--volume", str(policy) + ":/policy:ro,Z", tools_image,
                   "seinfo", "-t", target, "-x", "/policy"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        analysis["child_target_" + target] = {"command": command, "exit_code": result.returncode, "output": result.stdout, "stderr": result.stderr}
    (run / "policy-analysis.json").write_text(json.dumps(analysis, indent=2) + "\n")
    valid = all(value["exit_code"] == 0 for value in analysis.values())
    return {
        "security_loaded_policy_hash_matches": evidence.get("security_loaded_policy_hash", {}).get("exit_code") == 0 and checksum(policy) == evidence["security_loaded_policy_hash"]["output"].split()[0],
        "security_domain_no_unconfined_attributes": valid and "type sl_platformd_t," in analysis["domain"]["output"] and "unconfined" not in analysis["domain"]["output"],
        "security_domain_not_permissive": valid and "sl_platformd_t" not in analysis["permissive"]["output"],
        "security_entry_transition_loaded": valid and "type_transition init_t sl_platformd_exec_t:process sl_platformd_t;" in analysis["entry_transition"]["output"],
        "security_no_backend_escape_transition": valid and all("unconfined" not in analysis["child_target_" + target]["output"] for target in targets) and not any(name in analysis["child_transitions"]["output"] for name in ("install_t", "unconfined_t", "unconfined_service_t")),
        "security_negative_read_not_allowed": valid and not analysis["negative_read"]["output"].strip(),
        "security_raw_disk_read_not_allowed": valid and not analysis["raw_disk_read"]["output"].strip(),
        "security_generic_crypto_read_not_allowed": valid and not analysis["generic_crypto_read"]["output"].strip(),
        "security_generic_usr_directory_write_not_allowed": valid and not analysis["generic_usr_directory_write"]["output"].strip(),
        "security_generic_configuration_directory_write_not_allowed": valid and not analysis["generic_configuration_directory_write"]["output"].strip(),
        "security_named_lock_transition_loaded": valid and analysis["lock_transition"]["output"].strip() == "type_transition sl_platformd_t sl_platformd_ostree_t:file sl_platformd_lock_t lock;",
        "security_lock_parent_file_create_not_allowed": valid and not analysis["lock_parent_file_create"]["output"].strip(),
        "security_name_acquisition_scoped": valid and bool(analysis["service_acquire"]["output"].strip()) and not analysis["default_service_acquire"]["output"].strip(),
        "security_pid1_namespace_read_without_attach": valid and bool(analysis["pid1_namespace_read"]["output"].strip()) and not analysis["pid1_ptrace"]["output"].strip(),
    }


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
    parser.add_argument("--phase3b", action="store_true", help="Retain Phase 3A checks and validate confinement, bus boundaries and recovery")
    parser.add_argument("--policy-tools-image", default="localhost/slit-policy-tools:phase3b", help="Native setools build-stage image for analyzing the guest's loaded policy")
    parser.add_argument("--source-release", type=Path)
    parser.add_argument("--source-image", type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--cpus", type=int, default=2, help="Guest virtual CPU count (default: 2)")
    args = parser.parse_args()
    if args.phase3b:
        args.phase3a = True
    output = Path(__file__).resolve().parents[2] / "image/build/output"
    output.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="phase3b-" if args.phase3b else "phase3a-" if args.phase3a else "phase2b-", dir=output))
    report = {"phase": "3B" if args.phase3b else "3A" if args.phase3a else "2B", "result": "FAIL", "output": str(run), "checks": {}}
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
        if not 1 <= args.cpus <= 8:
            raise RuntimeError("Guest virtual CPU count must be between 1 and 8")
        if args.phase3b and args.timeout < 1800:
            raise RuntimeError("Phase 3B requires --timeout >= 1800")
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
                      acceleration=args.accel, virtual_cpus=args.cpus, timeout_seconds=args.timeout,
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
        if args.phase3b:
            extension = Path(__file__).with_name("guest-hardening-probe.sh")
            probe = probe.replace(marker, extension.read_text() + "\n" + marker)
            capture_marker = "    # Pipes allow confined command domains"
            if probe.count(capture_marker) != 1:
                raise RuntimeError("Guest command-capture marker is missing or ambiguous")
            probe = probe.replace(capture_marker, """    printf 'command_%s\\t0\\t' "$key" >&3
    printf '%q ' "$@" | base64 --wrap=0 >&3
    printf '\\n' >&3
""" + capture_marker)
            first_backend = "collect bootc_status bootc status --json"
            if probe.count(first_backend) != 1:
                raise RuntimeError("Independent backend observation marker is missing or ambiguous")
            early = """collect security_automatic_unit systemctl show sl-platformd.service --property=MainPID,ActiveState,SubState,DropInPaths
collect security_automatic_domain ps --no-headers -o pid,label,args -C sl-platformd
collect security_automatic_owner busctl --system --auto-start=no call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID s org.signallayer.Platform1
collect security_first_status /usr/bin/corectl status --json
collect security_initial_platform_journal journalctl --boot --no-pager --unit=sl-platformd.service
collect security_initial_failed_details sh -c 'systemctl --failed --no-legend --plain | while read -r unit unused; do systemctl status --no-pager --full "$unit"; journalctl --boot --no-pager --unit="$unit"; done'
"""
            probe = probe.replace(first_backend, early + first_backend)
            report["hardening_probe_sha256"] = checksum(extension)
            boundary = Path(__file__).with_name("guest-dbus-boundary.py")
            if probe.count("__SL_BOUNDARY_SOURCE__") != 1:
                raise RuntimeError("Guest boundary-source marker is missing or ambiguous")
            probe = probe.replace("__SL_BOUNDARY_SOURCE__", boundary.read_text())
            report["boundary_probe_sha256"] = checksum(boundary)
            subprocess.run(["podman", "image", "exists", args.policy_tools_image], check=True, timeout=30)
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
            "-cpu", "host" if args.accel == "kvm" else "max", "-smp", str(args.cpus), "-m", "2048",
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
                if args.phase3b:
                    report["checks"].update(evaluate_hardening(evidence))
                    report["checks"].update(inspect_loaded_policy(evidence, run, args.policy_tools_image))
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
