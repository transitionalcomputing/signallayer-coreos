#!/usr/bin/env python3
"""Offline P3-1a controls: plans never authorize payload or certify an image."""
from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from test_coreos_inventory import fixture, write

loader = importlib.machinery.SourceFileLoader("inventory_p31a", str(REPO / "tools/coreos-inventory"))
spec = importlib.util.spec_from_loader(loader.name, loader)
inv = importlib.util.module_from_spec(spec)
loader.exec_module(inv)


class PlannedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture(self.root)
        self.baseline = self.root / inv.DEFAULT_BASELINE
        self.baseline.parent.mkdir()
        self.planned = copy.deepcopy(json.loads((REPO / inv.DEFAULT_BASELINE).read_text())["planned_inventory"])
        # Tests use isolated small sources; real package locks are tested separately.
        self.planned["source_roots"] = ["management-lifecycle", "management-fixture", "image/management", "tools/build-management-rootfs", "config/coreos-installed-rpms-0.0.4.txt"]
        self.accept_fixture()

    def accept_fixture(self):
        """Establish an explicit reviewed fixture, never touch a repo baseline."""
        value = inv.document(self.root, "accepted")
        value["planned_inventory"] = self.planned
        self.baseline.write_text(json.dumps(value))
        self.contract = self.root / inv.DEFAULT_BUILD_CONTRACT
        self.contract.write_text(json.dumps({"schema_version": 1, "contract": inv.build_contract(self.root)}))

    def run_gate(self):
        return subprocess.run([sys.executable, str(REPO / "tools/coreos-inventory"), "--root", str(self.root), "--format", "json"], capture_output=True, text=True)

    def rejected(self, needle):
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(needle, result.stdout + result.stderr)

    def test_absent_planned_components_pass_without_installation_claim(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["planned_inventory"], "not-installed")
        self.assertEqual(evidence["installed_artifact_inventory"], "unproven")
        measured = inv.collect(self.root)
        self.assertNotIn("sl-management-lifecycle", measured["cargo_components"])
        self.assertFalse((self.root / "image/management").exists())

    def test_planned_name_does_not_authorize_materializing_any_surface(self):
        sources = {
            "unit": "image/management/sl-management-runtime.service",
            "sysusers": "image/management/sl-management.sysusers",
            "tmpfiles": "image/management/sl-management.tmpfiles",
            "container config": "image/management/containers.conf",
            "hook": "image/management/oci-hooks.d/host-hook.json",
            "policy": "image/management/selinux/sl_management.te",
            "Cargo component": "management-lifecycle/Cargo.toml",
            "Cargo binary": "management-fixture/src/main.rs",
            "sourced helper": "tools/build-management-rootfs",
            "final image lock": "config/coreos-installed-rpms-0.0.4.txt",
        }
        for label, source in sources.items():
            with self.subTest(surface=label):
                write(self.root / source, "unreviewed\n")
                self.rejected("build_contract.planned_source_inputs")
                (self.root / source).unlink()

    def test_unlisted_future_source_is_rejected(self):
        write(self.root / "image/management/unlisted.conf", "arbitrary\n")
        self.rejected("planned_source_inputs.image/management/unlisted.conf")

    def test_reviewed_future_inputs_are_bound_by_content_and_executable(self):
        paths = ["image/management/storage.conf", "image/management/oci-hooks.d/empty", "image/management/selinux/sl_management.fc", "tools/build-management-rootfs"]
        for path in paths:
            write(self.root / path, "reviewed fixture\n")
        self.accept_fixture()
        self.assertEqual(self.run_gate().returncode, 0)
        for source in paths:
            with self.subTest(source=source):
                path = self.root / source
                original = path.read_text()
                path.write_text("modified\n")
                self.rejected("planned_source_inputs." + source)
                path.write_text(original)
        helper = self.root / paths[-1]
        helper.chmod(0o755)
        self.rejected("planned_source_inputs.tools/build-management-rootfs.executable")

    def test_nonexecutable_checkout_permissions_are_portable(self):
        path = self.root / "tools/build-management-rootfs"
        write(path, "reviewed fixture\n")
        path.chmod(0o644)
        self.accept_fixture()
        for mode in (0o644, 0o664, 0o600):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                result = self.run_gate()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_executable_checkout_permissions_are_portable(self):
        path = self.root / "tools/build-management-rootfs"
        write(path, "reviewed fixture\n")
        path.chmod(0o755)
        self.accept_fixture()
        for mode in (0o755, 0o775, 0o700):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                result = self.run_gate()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_owner_executable_gain_and_loss_are_rejected(self):
        path = self.root / "tools/build-management-rootfs"
        write(path, "reviewed fixture\n")
        for before, after in ((0o644, 0o744), (0o755, 0o655)):
            with self.subTest(before=oct(before), after=oct(after)):
                path.chmod(before)
                self.accept_fixture()
                path.chmod(after)
                self.rejected("planned_source_inputs.tools/build-management-rootfs.executable")

    def test_file_symlink_substitution_is_rejected(self):
        path = self.root / "tools/build-management-rootfs"
        write(path, "reviewed fixture\n")
        self.accept_fixture()
        target = self.root / "identical-content"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        self.rejected("symlink in planned source input")

    def test_fresh_fixture_checkout_under_umask_002(self):
        path = self.root / "tools/build-management-rootfs"
        write(path, "reviewed fixture\n")
        path.chmod(0o644)
        self.accept_fixture()
        content = path.read_bytes()
        path.unlink()
        previous = os.umask(0o002)
        try:
            path.write_bytes(content)
        finally:
            os.umask(previous)
        self.assertEqual(path.stat().st_mode & 0o777, 0o664)
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_hook_directory_addition_is_detected(self):
        (self.root / "image/management/oci-hooks.d").mkdir(parents=True)
        self.rejected("planned_source_inputs")

    def test_reviewed_measurement_file_cannot_be_changed_or_deleted(self):
        source = "docs/base-lock.txt"
        self.planned["source_roots"].append(source)
        path = self.root / source
        write(path, "measured base fixture\n")
        self.accept_fixture()
        path.write_text("replaced lock\n")
        self.rejected("planned_source_inputs.docs/base-lock.txt")
        path.unlink()
        self.rejected("planned_source_inputs.docs/base-lock.txt")

    def test_symlink_source_or_ancestor_is_rejected(self):
        target = self.root / "outside"
        target.mkdir()
        (self.root / "management-lifecycle").symlink_to(target, target_is_directory=True)
        self.rejected("symlink in planned source input")

    def test_change_to_plan_is_not_self_approval(self):
        value = json.loads(self.baseline.read_text())
        value["planned_inventory"]["inventory"]["runtime_packages_declared"].append("skopeo")
        self.baseline.write_text(json.dumps(value))
        self.rejected("planned_inventory_sha256")

    def test_removing_plan_does_not_disable_gate(self):
        value = json.loads(self.baseline.read_text())
        del value["planned_inventory"]
        self.baseline.write_text(json.dumps(value))
        self.rejected("planned_inventory_sha256")

    def test_invalid_source_paths_are_rejected(self):
        for source in ("../escape", "/usr", "image/*", "image//management", "image/./management"):
            with self.subTest(source=source):
                value = json.loads(self.baseline.read_text())
                value["planned_inventory"]["source_roots"] = [source]
                self.baseline.write_text(json.dumps(value))
                self.rejected("invalid planned source root")

    def test_base_lock_cannot_be_promoted_to_installed_image_proof(self):
        value = json.loads(self.baseline.read_text())
        value["planned_inventory"]["final_image_inventory"]["status"] = "accepted"
        self.baseline.write_text(json.dumps(value))
        self.rejected("base evidence cannot certify")

    def test_runtime_directives_are_not_encoded_from_superseded_proposal(self):
        self.assertEqual(self.planned["runtime_directive_assertions"], "deferred-until-reviewed-P3-1d")
        value = json.loads(self.baseline.read_text())
        value["planned_inventory"]["runtime_directive_assertions"] = {"RestrictAddressFamilies": "AF_UNIX"}
        self.baseline.write_text(json.dumps(value))
        self.rejected("runtime directives are deferred")

    def test_cargo_autodiscovered_binary_addition_is_rejected(self):
        write(self.root / "app/src/bin/hidden.rs", "fn main() {}\n")
        self.rejected("cargo_binaries.sl-app/hidden")

    def test_explicit_cargo_binary_target_is_recorded_and_drift_rejected(self):
        path = self.root / "app/Cargo.toml"
        path.write_text(path.read_text() + '\n[[bin]]\nname="approved"\npath="src/tool.rs"\n')
        write(self.root / "app/src/tool.rs", "fn main() {}\n")
        self.accept_fixture()
        self.assertEqual(self.run_gate().returncode, 0)
        path.write_text(path.read_text().replace('name="approved"', 'name="different"'))
        self.rejected("cargo_binaries.sl-app/different")

    def test_planned_copy_still_requires_reviewed_instructions(self):
        # Even an existing, separately reviewed source does not approve COPY.
        write(self.root / "image/management/sl-management-reset.service", "[Service]\nExecStart=/usr/bin/true\n")
        self.accept_fixture()
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "COPY image/management/sl-management-reset.service /usr/lib/systemd/system/sl-management-reset.service\n")
        self.rejected("build_contract.stages[]")

    def test_sourcing_a_planned_helper_requires_instruction_review(self):
        write(self.root / "tools/build-management-rootfs", "# reviewed fixture\n")
        self.accept_fixture()
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("RUN printf '%s' safe >",
                        "RUN . /usr/lib/signallayer/build-management-rootfs && printf '%s' safe >"))
        self.rejected("build_contract.stages[]")

    def test_candidate_preserves_plan_without_approving_payload(self):
        output = self.root / "unapproved.json"
        result = subprocess.run([sys.executable, str(REPO / "tools/coreos-inventory"),
                                 "--root", str(self.root), "--candidate-output", str(output)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        generated = json.loads(output.read_text())
        self.assertEqual(generated["approval_status"], "unapproved")
        self.assertEqual(generated["planned_inventory"], self.planned)
        self.assertNotIn("sl-management-lifecycle", generated["inventory"]["cargo_components"])

    def test_renaming_installed_destination_is_rejected(self):
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("/usr/bin/sl-app\n", "/usr/bin/sl-other\n"))
        self.rejected("coreos_executables")

    def test_missing_malformed_plan_fails_closed(self):
        value = json.loads(self.baseline.read_text())
        value["planned_inventory"] = []
        self.baseline.write_text(json.dumps(value))
        self.rejected("planned inventory must be explicitly")

    def test_full_base_lock_and_surface_evidence_remain_distinct(self):
        planned = json.loads((REPO / inv.DEFAULT_BASELINE).read_text())["planned_inventory"]
        evidence = planned["base_rpm_evidence"]
        path = REPO / evidence["path"]
        self.assertEqual(inv.digest(path), evidence["sha256"])
        lines = path.read_text().splitlines()
        marker = "The following 543 NEVRAs are the complete installed package set in the pinned base:"
        values = lines[lines.index(marker) + 1:]
        self.assertEqual(len(values), 543)
        self.assertEqual(values, sorted(set(values)))
        self.assertEqual(evidence["scope"], "pinned-base-only")
        self.assertEqual(planned["final_image_inventory"]["status"], "unproven")
        self.assertEqual(len(planned["inventory"]["unit_masks"]), 15)
        self.assertEqual(len(planned["inventory"]["binfmt_masks"]), 31)
        self.assertFalse((REPO / planned["final_image_inventory"]["path"]).exists())

    def preflight_copy_context(self):
        # Reproduce file copies only, not RUN instructions or an image build.
        # This catches a gate that passes on the host but lacks its inputs in OCI.
        _, stages = inv.parse_stages((REPO / "Containerfile").read_text())
        stage = next(x for x in stages if x["alias"] == "release-preflight")
        destination = self.root / "preflight-context"
        destination.mkdir()
        for line in stage["instructions"]:
            if not line.startswith("COPY "):
                continue
            from_stage, paths = inv.parse_copy_tokens(line)
            self.assertIsNone(from_stage)
            target = destination / paths[-1].removeprefix("./")
            for source in paths[:-1]:
                path = REPO / source
                if path.is_dir():
                    shutil.copytree(path, target, dirs_exist_ok=True,
                                    ignore=shutil.ignore_patterns("__pycache__"))
                else:
                    output = target / path.name if paths[-1].endswith("/") else target
                    output.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, output)
        return destination

    def run_context_gate(self, destination):
        return subprocess.run([sys.executable, str(destination / "tools/coreos-inventory"),
                               "--root", str(destination), "--format", "json"],
                              capture_output=True, text=True)

    def test_oci_preflight_copy_context_contains_all_required_safeguards(self):
        result = self.run_context_gate(self.preflight_copy_context())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_oci_preflight_copy_context_tolerates_checkout_permissions(self):
        destination = self.preflight_copy_context()
        contract = json.loads((destination / inv.DEFAULT_BUILD_CONTRACT).read_text())["contract"]
        files = [destination / name for name, value in contract["planned_source_inputs"].items()
                 if value["state"] == "file"]
        self.assertTrue(files)
        for mode in (0o664, 0o600):
            with self.subTest(mode=oct(mode)):
                for path in files:
                    path.chmod(mode)
                result = self.run_context_gate(destination)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_oci_preflight_copy_context_rejects_owner_executable_drift(self):
        destination = self.preflight_copy_context()
        contract = json.loads((destination / inv.DEFAULT_BUILD_CONTRACT).read_text())["contract"]
        name = next(name for name, value in contract["planned_source_inputs"].items()
                    if value["state"] == "file")
        path = destination / name
        path.chmod(path.stat().st_mode ^ 0o100)
        result = self.run_context_gate(destination)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("planned_source_inputs." + name + ".executable", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
