"""Exercise preparation's real control flow with deterministic OS boundaries.

No RPM is installed and no image is built. Namespace, signing-key bootstrap and
RPM-body validation have separate direct tests; here their successful outcomes
and subprocess measurements are simulated so every main() acceptance gate is
reachable without requiring privileges or trusting a discovered inventory.
"""

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "preparation_execution_subject", ROOT / "tools/static-toolchain/prepare.py"
)
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
LOCK_PATH = ROOT / "config/static-fixture-toolchain.json"
BASE_RECORD = ROOT / "docs/development/0.0.4-phase1-pass3-installed-nevras.txt"


def recorded_base():
    """Read the independently measured base record, never lock final inventory."""
    pattern = re.compile(r"[A-Za-z0-9+_.~\-]+-[0-9]+:[^\s]+\.(?:x86_64|noarch|\(none\))\Z")
    lines = (line.split("#", 1)[0].strip() for line in BASE_RECORD.read_text().splitlines())
    return sorted(line for line in lines if pattern.fullmatch(line))


def package_identity(nevra):
    body, architecture = nevra.rsplit(".", 1)
    name, epoch_version, release = body.rsplit("-", 2)
    if ":" not in epoch_version or not release:
        raise AssertionError("invalid independently parsed NEVRA")
    return name, architecture


class IndependentInventoryArithmeticTests(unittest.TestCase):
    def test_lock_inventory_is_derived_from_pinned_base_plus_exact_transaction_and_key(self):
        lock = json.loads(LOCK_PATH.read_bytes())
        base = recorded_base()
        self.assertEqual(len(base), 543)
        self.assertEqual(len(set(base)), 543)
        base_by_identity = {package_identity(value): value for value in base}
        self.assertEqual(len(base_by_identity), 543)
        transaction = {package["nevra"] for package in lock["packages"]}
        self.assertEqual(len(transaction), 23)
        transaction_identities = {package_identity(value) for value in transaction}
        replaced = {base_by_identity[identity] for identity in transaction_identities
                    if identity in base_by_identity}
        self.assertEqual({package_identity(value)[0] for value in replaced}, {
            "glibc", "glibc-common", "glibc-gconv-extra", "glibc-minimal-langpack"
        })
        self.assertEqual(len(replaced), 4)
        self.assertTrue(all(value.endswith("-0:2.43-8.fc44.x86_64") for value in replaced))
        key = "gpg-pubkey-0:36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6-6786af3b.(none)"
        self.assertEqual(lock["signing_key_nevra"], key)
        self.assertNotIn(key, base)
        self.assertNotIn(key, transaction)
        derived = sorted((set(base) - replaced) | transaction | {key})
        self.assertEqual(len(derived), 543 - 4 + 23 + 1)
        self.assertEqual(len(derived), 563)
        self.assertEqual(lock["installed_nevras"], derived)
        digest = hashlib.sha256(("\n".join(base) + "\n").encode("ascii")).hexdigest()
        self.assertEqual(lock["base"]["installed_nevras_sha256"], digest)


class PreparationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name)
        self.lock_bytes = LOCK_PATH.read_bytes()
        self.lock = json.loads(self.lock_bytes)
        (self.build / "lock.json").write_bytes(self.lock_bytes)
        self.base = recorded_base()
        self.final = list(self.lock["installed_nevras"])
        self.paths = [str(self.build / "rpms" / package["filename"])
                      for package in sorted(self.lock["packages"], key=lambda item: item["filename"])]
        self.signatures = {Path(path).name: "synthetic successful signature result"
                           for path in self.paths}
        self.expected_install = [
            "dnf", "-y", "--disablerepo=*", "--setopt=install_weak_deps=False",
            "install", *self.paths,
        ]
        versions = self.lock["versions"]
        self.tool_outputs = {
            ("rustc", "--version"): f"rustc {versions['rust']} (synthetic-test-record)\n",
            ("cargo", "--version"): f"cargo {versions['cargo']} (synthetic-test-record)\n",
            ("gcc", "-dumpfullversion"): versions["gcc"] + "\n",
            ("ld", "--version"): "GNU ld version " + versions["binutils"] + "\n",
            ("gcc", "--version"): "synthetic gcc verbose record\n",
            ("rustc", "-vV"): "synthetic rustc verbose record\n",
        }
        self.events = []
        self.commands = []
        self.inventory_calls = 0
        self.install_failure = None
        patches = {
            "BUILD": self.build,
            "require_rootless_build_namespace": mock.Mock(side_effect=lambda: self.events.append("namespace")),
            "initialize_signing_key": mock.Mock(side_effect=self.key_boundary),
            "verify_rpms": mock.Mock(side_effect=self.rpm_boundary),
            "run": mock.Mock(side_effect=self.command_boundary),
        }
        self.patches = {}
        for name, replacement in patches.items():
            patch = mock.patch.object(PREP, name, replacement)
            self.patches[name] = patch.start()
            self.addCleanup(patch.stop)
        self.output = io.StringIO()

    def key_boundary(self, lock):
        self.assertEqual(lock, self.lock)
        self.events.append("key-validation")
        return "synthetic existing trusted key record"

    def rpm_boundary(self, lock):
        self.assertEqual(lock, self.lock)
        self.events.append("rpm-validation")
        return self.paths, self.signatures

    def command_boundary(self, argv, **kwargs):
        """Only replace external measurements; do not duplicate main's gates."""
        self.commands.append((list(argv), kwargs))
        if argv == ["rpm", "-qa", "--qf", PREP.RPM_QUERY]:
            self.inventory_calls += 1
            if self.inventory_calls == 1:
                self.events.append("base-measurement")
                return "\n".join(self.base) + "\n"
            if self.inventory_calls == 2:
                self.events.append("final-measurement")
                return "\n".join(self.final) + "\n"
            self.fail("unexpected additional inventory measurement")
        if argv and argv[0] == "dnf":
            self.events.append("install")
            if self.install_failure:
                raise PREP.PreparationError(self.install_failure)
            return "synthetic offline installation result\n"
        if tuple(argv) in self.tool_outputs:
            self.events.append("version-measurement")
            return self.tool_outputs[tuple(argv)]
        self.fail(f"unexpected external command: {argv!r}")

    def call_main(self):
        with redirect_stdout(self.output):
            PREP.main()

    def assert_no_evidence(self):
        self.assertFalse((self.build / "preparation-evidence.json").exists())
        self.assertEqual(list(self.build.glob(".preparation-*")), [])
        self.assertNotIn("PASS:", self.output.getvalue())

    def refused(self, reason):
        with self.assertRaisesRegex(PREP.PreparationError, reason):
            self.call_main()
        self.assert_no_evidence()

    def test_namespace_guard_precedes_lock_reads_and_installation(self):
        self.patches["require_rootless_build_namespace"].side_effect = PREP.PreparationError(
            "synthetic namespace rejected"
        )
        with mock.patch.object(PREP, "regular_bytes", wraps=PREP.regular_bytes) as reads:
            self.refused("synthetic namespace rejected")
            reads.assert_not_called()
        self.patches["initialize_signing_key"].assert_not_called()
        self.patches["verify_rpms"].assert_not_called()
        self.patches["run"].assert_not_called()

    def test_base_inventory_drift_prevents_installation_and_evidence(self):
        self.base.append("unexpected-base-0:1-1.x86_64")
        self.refused("actual base RPM inventory differs")
        self.assertEqual(self.events, ["namespace", "base-measurement"])
        self.patches["initialize_signing_key"].assert_not_called()
        self.patches["verify_rpms"].assert_not_called()
        self.assertFalse(any(argv[0] == "dnf" for argv, _ in self.commands))

    def test_postinstall_extra_package_prevents_evidence(self):
        self.final.append("unexpected-builder-0:1-1.x86_64")
        self.refused("installed toolchain closure differs")
        self.assertNotIn("version-measurement", self.events)

    def test_postinstall_missing_package_prevents_evidence(self):
        self.final.remove(next(value for value in self.final if value.startswith("gcc-0:")))
        self.refused("installed toolchain closure differs")
        self.assertNotIn("version-measurement", self.events)

    def test_postinstall_replaced_package_prevents_evidence(self):
        previous = next(value for value in self.final if value.startswith("glibc-0:"))
        self.final.remove(previous)
        self.final.append("glibc-0:2.43-8.fc44.x86_64")
        self.refused("installed toolchain closure differs")
        self.assertNotIn("version-measurement", self.events)

    def test_measured_rust_version_mismatch_prevents_evidence(self):
        self.tool_outputs[("rustc", "--version")] = "rustc 0.0.0 (wrong-measurement)\n"
        self.refused("actual rust version differs")

    def test_measured_cargo_version_mismatch_prevents_evidence(self):
        self.tool_outputs[("cargo", "--version")] = "cargo 0.0.0 (wrong-measurement)\n"
        self.refused("actual cargo version differs")

    def test_measured_gcc_version_mismatch_prevents_evidence(self):
        self.tool_outputs[("gcc", "-dumpfullversion")] = "0.0.0\n"
        self.refused("actual gcc version differs")

    def test_measured_binutils_version_mismatch_prevents_evidence(self):
        self.tool_outputs[("ld", "--version")] = "GNU ld version 0.0.0\n"
        self.refused("actual GNU ld version differs")

    def test_exact_offline_install_argv_and_success_evidence(self):
        self.call_main()
        installations = [(argv, options) for argv, options in self.commands if argv[0] == "dnf"]
        self.assertEqual(installations, [(self.expected_install, {"timeout": 600})])
        self.assertEqual(self.events[:6], ["namespace", "base-measurement", "key-validation",
                                          "rpm-validation", "install", "final-measurement"])
        record = json.loads((self.build / "preparation-evidence.json").read_bytes())
        self.assertEqual(record["base_nevras"], self.base)
        self.assertEqual(record["installed_nevras"], self.final)
        self.assertEqual(record["installation_command"], self.expected_install)
        self.assertEqual(record["lock_sha256"], hashlib.sha256(self.lock_bytes).hexdigest())
        self.assertEqual(record["versions"], self.lock["versions"])
        self.assertEqual(record["rpm_signatures"], self.signatures)
        self.assertFalse(record["production_coreos_changed"])
        self.assertIn("PASS: isolated offline static-build toolchain matches its lock", self.output.getvalue())

    def test_installation_command_failure_prevents_evidence(self):
        self.install_failure = "synthetic offline installation failure"
        self.refused(self.install_failure)
        self.assertEqual(self.inventory_calls, 1)
        self.assertNotIn("final-measurement", self.events)

    def test_failed_key_validation_prevents_installation_and_evidence(self):
        self.patches["initialize_signing_key"].side_effect = PREP.PreparationError("synthetic key refusal")
        self.refused("synthetic key refusal")
        self.patches["verify_rpms"].assert_not_called()
        self.assertFalse(any(argv[0] == "dnf" for argv, _ in self.commands))

    def test_failed_rpm_validation_prevents_installation_and_evidence(self):
        self.patches["verify_rpms"].side_effect = PREP.PreparationError("synthetic RPM refusal")
        self.refused("synthetic RPM refusal")
        self.assertFalse(any(argv[0] == "dnf" for argv, _ in self.commands))


if __name__ == "__main__":
    unittest.main()
