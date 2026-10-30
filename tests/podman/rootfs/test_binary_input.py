"""Hostile offline artifact-input fixtures; no binary execution or runtime proof.

Only private test checkouts receive a synthetic ELF pin. The reviewed production
lock, fixture source and binary are never changed or fabricated by these tests.
"""

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_rootfs import ROOT, fixture_checkout, load_tool, synthetic_elf


class CapturedArtifactControlTests(unittest.TestCase):
    """Portable control-flow tests, explicitly mocking only fd capture.

    These never establish Linux path/metadata safety; BinaryInputFixtures below
    tests that boundary using real Linux descriptors and mount identities.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sl-artifact-control-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo, self.artifact = fixture_checkout(self.base)
        self.builder = load_tool("build-management-rootfs", self.repo)
        self.payload = synthetic_elf()
        self.snapshot = {str(path.relative_to(self.builder.SOURCE_ROOT)): path.read_bytes()
                         for path in self.builder.SOURCE_ROOT.rglob("*") if path.is_file()}
        self.capture = mock.patch.object(self.builder, "regular_snapshot", side_effect=self.capture_boundary)
        self.capture_mock = self.capture.start()
        self.addCleanup(self.capture.stop)
        self.pin = self.builder.reviewed_artifact(self.snapshot)
        self.capture_mock.reset_mock()

    def capture_boundary(self, path, maximum, artifact=False):
        self.assertIn(Path(path), (self.artifact, self.builder.ARTIFACT_LOCK,
                                  self.builder.ARTIFACT_CONTRACT, self.builder.STATIC_VERIFIER))
        return Path(path).read_bytes()

    def rewrite_lock_and_test_contract(self, lock):
        data = json.dumps(lock, sort_keys=True).encode()
        self.builder.ARTIFACT_LOCK.write_bytes(data)
        contract = json.loads(self.builder.ARTIFACT_CONTRACT.read_bytes())
        contract["inputs_sha256"]["config/static-fixture-toolchain.json"] = hashlib.sha256(data).hexdigest()
        self.builder.ARTIFACT_CONTRACT.write_text(json.dumps(contract))

    def synthetic_checker_success(self, pin=None):
        """A controlled boundary result, not proof that hostile bytes pass ELF."""
        pin = self.pin if pin is None else pin
        return subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "status": "PASS", "scope": "development-static-ELF-only",
            "sha256": pin["sha256"], "bytes": pin["size"], "machine": "x86_64",
        }), stderr="")

    def test_fixed_source_lock_contract_and_verifier_pin_are_bound(self):
        pin = self.builder.reviewed_artifact(self.snapshot)
        self.assertEqual(pin["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(pin["size"], 512)
        self.assertEqual(pin["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(pin["source_sha256"], hashlib.sha256(self.snapshot["src/main.rs"]).hexdigest())
        self.assertEqual(pin["lock_sha256"], hashlib.sha256(self.builder.ARTIFACT_LOCK.read_bytes()).hexdigest())
        self.assertEqual(pin["verifier_sha256"], hashlib.sha256(self.builder.STATIC_VERIFIER.read_bytes()).hexdigest())
        self.assertEqual([Path(call.args[0]) for call in self.capture_mock.call_args_list],
                         [self.builder.ARTIFACT_LOCK, self.builder.ARTIFACT_CONTRACT])

    def test_lock_drift_is_not_self_approved(self):
        self.builder.ARTIFACT_LOCK.write_bytes(self.builder.ARTIFACT_LOCK.read_bytes() + b"\n")
        with self.assertRaises(self.builder.BuildError):
            self.builder.reviewed_artifact(self.snapshot)

    def test_source_drift_does_not_authorize_the_same_binary(self):
        self.snapshot["src/main.rs"] += b"\n// unreviewed source\n"
        with self.assertRaises(self.builder.BuildError):
            self.builder.reviewed_artifact(self.snapshot)

    def test_wrong_target_is_rejected_even_with_coherent_test_lock_hash(self):
        lock = json.loads(self.builder.ARTIFACT_LOCK.read_bytes())
        lock["target"] = "aarch64-unknown-linux-gnu"
        self.rewrite_lock_and_test_contract(lock)
        with self.assertRaises(self.builder.BuildError):
            self.builder.reviewed_artifact(self.snapshot)

    def test_malformed_or_unbounded_reviewed_pin_is_rejected(self):
        original = json.loads(self.builder.ARTIFACT_LOCK.read_bytes())
        for artifact in ({"sha256": "0" * 64, "size": 0},
                         {"sha256": "0" * 64, "size": self.builder.MAX_BYTES + 1},
                         {"sha256": "A" * 64, "size": 512},
                         {"sha256": "0" * 64, "size": True},
                         {"sha256": "0" * 64, "size": 512, "extra": True}):
            lock = dict(original, artifact=artifact)
            self.rewrite_lock_and_test_contract(lock)
            with self.subTest(artifact=artifact), self.assertRaises(self.builder.BuildError):
                self.builder.reviewed_artifact(self.snapshot)

    def test_manifest_uses_source_pin_not_supplied_artifact_bytes(self):
        self.artifact.chmod(0o600)
        self.artifact.write_bytes(bytes(len(self.payload)))
        manifest = self.builder.expected_manifest(self.snapshot, self.pin)
        entry = next(item for item in manifest["entries"]
                     if item["path"] == "usr/bin/sl-management-fixture")
        self.assertEqual(entry["sha256"], self.pin["sha256"])
        self.assertEqual((entry["uid"], entry["gid"], entry["mode"]), (0, 0, 0o555))
        provenance = {item["path"]: item["sha256"] for item in manifest["source"]["inputs"]}
        self.assertEqual(provenance["config/static-fixture-toolchain.json"], self.pin["lock_sha256"])
        self.assertEqual(provenance["config/static-fixture-toolchain.contract.json"], self.pin["contract_sha256"])
        self.assertEqual(manifest["dynamic_mounts"], [])

    def test_independent_manifest_parser_accepts_the_source_derived_binary_entry(self):
        verifier = load_tool("verify-management-rootfs", self.repo)
        manifest = self.builder.expected_manifest(self.snapshot, self.pin)
        parsed = verifier._validate_manifest(self.builder.canonical(manifest))
        self.assertEqual(parsed, manifest)
        self.assertEqual(next(item for item in parsed["entries"]
                              if item["path"] == "usr/bin/sl-management-fixture")["sha256"],
                         self.pin["sha256"])

    def test_manifest_cannot_change_the_fixed_executable_destination_or_mode(self):
        original = json.loads(self.snapshot["rootfs-spec.json"])
        for field, value in (("path", "usr/bin/unreviewed-executable"), ("mode", 0o544)):
            recipe = json.loads(json.dumps(original))
            entry = next(item for item in recipe["entries"]
                         if item["path"] == "usr/bin/sl-management-fixture")
            entry[field] = value
            recipe["entries"].sort(key=lambda item: item["path"])
            snapshot = dict(self.snapshot, **{"rootfs-spec.json": self.builder.canonical(recipe)})
            with self.subTest(field=field), self.assertRaises(self.builder.BuildError):
                self.builder.expected_manifest(snapshot, self.pin)

    def test_manifest_refuses_omission_of_the_fixed_executable(self):
        recipe = json.loads(self.snapshot["rootfs-spec.json"])
        recipe["entries"] = [item for item in recipe["entries"]
                             if item["path"] != "usr/bin/sl-management-fixture"]
        snapshot = dict(self.snapshot, **{"rootfs-spec.json": self.builder.canonical(recipe)})
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot, self.pin)

    def test_production_source_oracle_matches_reviewed_golden_without_materialization(self):
        builder = load_tool("build-management-rootfs")
        snapshot = {str(path.relative_to(builder.SOURCE_ROOT)): path.read_bytes()
                    for path in builder.SOURCE_ROOT.rglob("*") if path.is_file()}
        expected_paths = {builder.ARTIFACT_LOCK, builder.ARTIFACT_CONTRACT}
        def captured(path, maximum):
            self.assertIn(Path(path), expected_paths)
            return Path(path).read_bytes()
        with mock.patch.object(builder, "regular_snapshot", side_effect=captured), \
                mock.patch.object(builder.tempfile, "mkdtemp", side_effect=AssertionError("must not materialize")):
            manifest = builder.expected_manifest(snapshot)
        golden = json.loads((ROOT / "tests/podman/rootfs/expected-source-identity.json").read_bytes())
        self.assertEqual(golden, {
            "build_id": manifest["build_id"],
            "manifest_sha256": hashlib.sha256(builder.canonical(manifest)).hexdigest(),
        })

    def test_same_size_wrong_capture_fails_before_checker(self):
        self.artifact.chmod(0o600)
        self.artifact.write_bytes(bytes(len(self.payload)))
        with mock.patch.object(self.builder.subprocess, "run", return_value=self.synthetic_checker_success()) as checker:
            with self.assertRaises(self.builder.BuildError):
                self.builder.read_artifact(self.artifact, self.pin)
            checker.assert_not_called()

    def test_wrong_capture_size_fails_before_checker(self):
        wrong = dict(self.pin, size=len(self.payload) + 1)
        with mock.patch.object(self.builder.subprocess, "run", return_value=self.synthetic_checker_success(wrong)) as checker:
            with self.assertRaises(self.builder.BuildError):
                self.builder.read_artifact(self.artifact, wrong)
            checker.assert_not_called()

    def test_changed_checker_source_is_not_executed(self):
        self.builder.STATIC_VERIFIER.write_bytes(self.builder.STATIC_VERIFIER.read_bytes() + b"\n")
        with mock.patch.object(self.builder.subprocess, "run", return_value=self.synthetic_checker_success()) as checker:
            with self.assertRaises(self.builder.BuildError):
                self.builder.read_artifact(self.artifact, self.pin)
            checker.assert_not_called()

    def test_actual_static_parser_refuses_malformed_elf_with_a_coherent_private_test_pin(self):
        malformed = bytes(512)
        self.artifact.chmod(0o600)
        self.artifact.write_bytes(malformed)
        lock = json.loads(self.builder.ARTIFACT_LOCK.read_bytes())
        lock["artifact"] = {"sha256": hashlib.sha256(malformed).hexdigest(), "size": len(malformed)}
        self.rewrite_lock_and_test_contract(lock)
        private_pin = self.builder.reviewed_artifact(self.snapshot)
        real_run = self.builder.subprocess.run
        with mock.patch.object(self.builder.subprocess, "run", wraps=real_run) as checker:
            with self.assertRaises(self.builder.BuildError):
                self.builder.read_artifact(self.artifact, private_pin)
        checker.assert_called_once()

    def test_private_checker_capture_gets_the_reviewed_hash_and_exact_bytes(self):
        real_run = self.builder.subprocess.run
        def checked(argv, **options):
            self.assertEqual(argv[:3], [sys.executable, "-I", "-B"])
            checker, capture = Path(argv[3]), Path(argv[5])
            self.assertEqual(checker.name, "verify-static-fixture")
            self.assertNotEqual(checker, self.builder.STATIC_VERIFIER)
            self.assertEqual(checker.read_bytes(), self.builder.STATIC_VERIFIER.read_bytes())
            self.assertEqual(checker.parent, capture.parent)
            self.assertEqual(argv[4], "--artifact")
            self.assertEqual(capture.read_bytes(), self.payload)
            self.assertEqual(argv[6:], ["--expected-sha256", self.pin["sha256"]])
            self.assertEqual(options["timeout"], 30)
            self.assertIs(options["shell"], False)
            return real_run(argv, **options)
        with mock.patch.object(self.builder.subprocess, "run", side_effect=checked) as process:
            self.assertEqual(self.builder.read_artifact(self.artifact, self.pin), self.payload)
            process.assert_called_once()
        self.assertEqual(sum(Path(call.args[0]) == self.artifact
                             for call in self.capture_mock.call_args_list), 1)

    def test_unavailable_or_refusing_checker_never_returns_accepted_bytes(self):
        for result in (subprocess.CompletedProcess([], 1, stdout="{}", stderr="refused"),
                       subprocess.CompletedProcess([], 0, stdout="not-json", stderr="")):
            with self.subTest(result=result), mock.patch.object(self.builder.subprocess, "run", return_value=result):
                with self.assertRaises(self.builder.BuildError):
                    self.builder.read_artifact(self.artifact, self.pin)

    def test_wrong_checker_identity_is_refused(self):
        good = {"status": "PASS", "scope": "development-static-ELF-only",
                "sha256": self.pin["sha256"], "bytes": self.pin["size"], "machine": "x86_64"}
        for field, value in (("status", "FAIL"), ("scope", "wrong"), ("sha256", "0" * 64),
                             ("bytes", 513), ("machine", "aarch64")):
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps(dict(good, **{field: value})), stderr="")
            with self.subTest(field=field), mock.patch.object(self.builder.subprocess, "run", return_value=result):
                with self.assertRaises(self.builder.BuildError):
                    self.builder.read_artifact(self.artifact, self.pin)

    def test_checker_timeout_is_a_controlled_refusal(self):
        with mock.patch.object(self.builder.subprocess, "run", side_effect=subprocess.TimeoutExpired("checker", 30)):
            with self.assertRaises(self.builder.BuildError):
                self.builder.read_artifact(self.artifact, self.pin)


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires disposable rootless Linux uid 0 and real fd/mount APIs")
class BinaryInputFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sl-binary-input-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo, self.artifact = fixture_checkout(self.base)
        self.builder = load_tool("build-management-rootfs", self.repo)
        self.elf = load_tool("verify-static-fixture", self.repo)
        self.payload = synthetic_elf()
        self.snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        self.pin = self.builder.reviewed_artifact(self.snapshot)
        self.output = self.base / "bundle"

    def test_full_build_rejects_unreviewed_same_size_elf(self):
        # Capture the trusted oracle BEFORE introducing any caller substitution.
        # This is the fixed private test pin, never the real F5 artifact/golden.
        expected = self.builder.expected_manifest(self.snapshot, self.pin)
        expected_bytes = self.builder.canonical(expected)
        expected_digest = hashlib.sha256(expected_bytes).hexdigest()
        protected = [self.builder.ARTIFACT_LOCK, self.builder.ARTIFACT_CONTRACT,
                     self.builder.SOURCE_ROOT / "rootfs-spec.json",
                     ROOT / "config/static-fixture-toolchain.json",
                     ROOT / "config/static-fixture-toolchain.contract.json",
                     ROOT / "tests/podman/rootfs/expected-source-identity.json"]
        source_before = {path: path.read_bytes() for path in protected}
        verifier = load_tool("verify-management-rootfs", self.repo)

        # No builder/helper/subprocess mocks: the known-good full path and both
        # independent verifiers must work in this actual disposable filesystem.
        good = self.base / "known-good"
        result = self.builder.build_bundle(good, self.artifact)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["manifest_sha256"], expected_digest)
        self.assertEqual(result["build_id"], expected["build_id"])
        self.assertEqual((good / "manifest.json").read_bytes(), expected_bytes)
        self.assertEqual(verifier.verify_bundle(good, expected_digest)["status"], "PASS")
        self.assertEqual((good / "rootfs/usr/bin/sl-management-fixture").read_bytes(), self.payload)

        supplied = bytearray(self.payload)
        supplied[-1] ^= 0x5A  # Change loadable bytes, not ELF structure or size.
        supplied = bytes(supplied)
        self.assertEqual(len(supplied), self.pin["size"])
        self.assertNotEqual(hashlib.sha256(supplied).hexdigest(), self.pin["sha256"])
        self.assertEqual(self.elf.parse_elf(supplied)["machine"], "x86_64")
        unreviewed = self.base / "unreviewed-regular-elf"
        unreviewed.write_bytes(supplied)
        unreviewed.chmod(0o555)

        rejection = None
        try:
            self.builder.build_bundle(self.output, unreviewed)
        except self.builder.BuildError as error:
            rejection = str(error)
        # This assertion is the full acceptance boundary. A caller-authority
        # regression must fail here, not through an incidental helper error.
        self.assertFalse(self.output.exists(),
                         "full build published an unreviewed same-size valid ELF")
        self.assert_no_bundle()
        self.assertIsNotNone(rejection, "full build did not reject caller bytes")
        self.assertIn("artifact SHA-256 mismatch", rejection)
        after = self.builder.expected_manifest(self.builder.source_snapshot(self.builder.SOURCE_ROOT))
        self.assertEqual(self.builder.canonical(after), expected_bytes)
        self.assertEqual({path: path.read_bytes() for path in protected}, source_before)
        self.assertEqual((good / "manifest.json").read_bytes(), expected_bytes)
        self.assertEqual(verifier.verify_bundle(good, expected_digest)["status"], "PASS")

    def write_artifact(self, payload):
        self.artifact.chmod(0o600)
        self.artifact.write_bytes(payload)
        self.artifact.chmod(0o555)

    def read(self, path=None, pin=None):
        return self.builder.read_artifact(path or self.artifact, pin or self.pin)

    def refused(self, path=None, pin=None):
        with self.assertRaises((self.builder.BuildError, OSError)):
            self.read(path, pin)

    def assert_no_bundle(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.base.glob(".sl-rootfs-*")), [])

    def test_private_synthetic_pin_is_distinct_from_the_reviewed_native_artifact(self):
        production = json.loads((ROOT / "config/static-fixture-toolchain.json").read_bytes())
        self.assertNotEqual(self.pin["sha256"], production["artifact"]["sha256"])
        self.assertEqual(self.pin["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.pin["size"], 512)
        self.assertEqual(self.read(), self.payload)

    def test_reviewed_pin_binds_fixed_source_target_and_exact_lock_bytes(self):
        lock_bytes = self.builder.ARTIFACT_LOCK.read_bytes()
        lock = json.loads(lock_bytes)
        self.assertEqual(self.pin["source_sha256"], hashlib.sha256(self.snapshot["src/main.rs"]).hexdigest())
        self.assertEqual(self.pin["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(self.pin["lock_sha256"], hashlib.sha256(lock_bytes).hexdigest())
        self.assertEqual(self.pin["sha256"], lock["artifact"]["sha256"])
        self.assertEqual(self.pin["size"], lock["artifact"]["size"])

    def test_missing_trusted_lock_has_no_input_hash_fallback(self):
        self.builder.ARTIFACT_LOCK.unlink()
        with self.assertRaises((self.builder.BuildError, OSError)):
            self.builder.reviewed_artifact(self.snapshot)

    def test_changed_fixture_source_is_not_authorized_by_unchanged_binary(self):
        changed = dict(self.snapshot)
        changed["src/main.rs"] += b"\n// unreviewed source\n"
        with self.assertRaises(self.builder.BuildError):
            self.builder.reviewed_artifact(changed)

    def test_wrong_target_or_source_binding_in_lock_is_rejected(self):
        original = self.builder.ARTIFACT_LOCK.read_bytes()
        for field in ("target", "source"):
            lock = json.loads(original)
            if field == "target":
                lock["target"] = "aarch64-unknown-linux-gnu"
            else:
                lock["source"]["sha256"] = "0" * 64
            self.builder.ARTIFACT_LOCK.write_text(json.dumps(lock))
            with self.subTest(field=field), self.assertRaises(self.builder.BuildError):
                self.builder.reviewed_artifact(self.snapshot)

    def test_missing_input_is_refused(self):
        self.artifact.unlink()
        self.refused()

    def test_wrong_same_size_bytes_fail_before_static_checker(self):
        self.write_artifact(bytes(len(self.payload)))
        with mock.patch.object(self.builder.subprocess, "run") as checker:
            self.refused()
            checker.assert_not_called()

    def test_truncated_and_oversized_inputs_fail_before_static_checker(self):
        for size in (len(self.payload) - 1, self.builder.MAX_BYTES + 1):
            self.artifact.chmod(0o600)
            with self.artifact.open("wb") as stream:
                stream.truncate(size)
            self.artifact.chmod(0o555)
            with self.subTest(size=size), mock.patch.object(self.builder.subprocess, "run") as checker:
                self.refused()
                checker.assert_not_called()

    def test_wrong_expected_pin_cannot_be_learned_from_supplied_bytes(self):
        for field, value in (("sha256", "0" * 64), ("size", len(self.payload) + 1)):
            wrong = dict(self.pin, **{field: value})
            with self.subTest(field=field), mock.patch.object(self.builder.subprocess, "run") as checker:
                self.refused(pin=wrong)
                checker.assert_not_called()

    def test_symlink_input_is_never_followed(self):
        target = self.base / "real-input"
        self.artifact.rename(target)
        self.artifact.symlink_to(target)
        self.refused()

    def test_symlink_ancestor_is_never_followed(self):
        parent = self.base / "real-parent"
        parent.mkdir(mode=0o700)
        target = parent / "fixture"
        self.artifact.rename(target)
        alias = self.base / "ancestor-alias"
        alias.symlink_to(parent, target_is_directory=True)
        self.refused(alias / "fixture")

    def test_external_hardlink_alias_is_refused(self):
        os.link(self.artifact, self.base / "outside-alias")
        self.assertEqual(self.artifact.stat().st_nlink, 2)
        self.refused()

    def test_special_permission_bits_are_refused(self):
        for mode in (0o4555, 0o2555, 0o1555):
            self.artifact.chmod(mode)
            self.assertEqual(stat.S_IMODE(self.artifact.stat().st_mode), mode)
            with self.subTest(mode=oct(mode)):
                self.refused()

    def test_group_or_world_writable_input_parent_is_refused(self):
        parent = self.base / "writable-parent"
        parent.mkdir(mode=0o700)
        target = parent / "fixture"
        self.artifact.rename(target)
        for mode in (0o770, 0o707):
            parent.chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.refused(target)
        parent.chmod(0o700)

    def test_directory_fifo_and_unix_socket_inputs_are_refused(self):
        self.artifact.unlink()
        self.artifact.mkdir()
        self.refused()
        self.artifact.rmdir()
        os.mkfifo(self.artifact)
        self.refused()
        self.artifact.unlink()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.bind(str(self.artifact))
        self.refused()

    def test_device_type_metadata_is_refused_without_creating_a_device(self):
        real_fstat = self.builder.os.fstat
        inode = self.artifact.stat().st_ino
        def changed(descriptor):
            value = real_fstat(descriptor)
            if value.st_ino == inode:
                fields = {name: getattr(value, name) for name in (
                    "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                    "st_nlink", "st_mtime_ns", "st_ctime_ns")}
                fields["st_mode"] = stat.S_IFCHR | 0o555
                return SimpleNamespace(**fields)
            return value
        with mock.patch.object(self.builder.os, "fstat", side_effect=changed):
            self.refused()

    def artifact_xattrs(self, names):
        real_list = self.builder.os.listxattr
        inode = self.artifact.stat().st_ino
        def listing(descriptor, *args, **kwargs):
            info = os.fstat(descriptor) if isinstance(descriptor, int) else os.lstat(descriptor)
            if info.st_ino == inode:
                return names
            return real_list(descriptor, *args, **kwargs)
        return mock.patch.object(self.builder.os, "listxattr", side_effect=listing)

    def test_capabilities_acl_and_other_unreviewed_xattrs_are_refused(self):
        for name in ("security.capability", "system.posix_acl_access", "user.unreviewed"):
            with self.subTest(name=name), self.artifact_xattrs([name]):
                self.refused()

    def test_selinux_attribute_is_not_mistaken_for_installed_label_proof(self):
        with self.artifact_xattrs(["security.selinux"]):
            self.assertEqual(self.read(), self.payload)

    def test_content_change_during_read_is_refused(self):
        real_read = self.builder.os.read
        inode = self.artifact.stat().st_ino
        changed = False
        def reading(descriptor, length):
            nonlocal changed
            data = real_read(descriptor, length)
            if not changed and data and os.fstat(descriptor).st_ino == inode:
                changed = True
                self.write_artifact(bytes(len(self.payload)))
            return data
        with mock.patch.object(self.builder.os, "read", side_effect=reading):
            self.refused()
        self.assertTrue(changed)

    def test_mount_identity_substitution_is_refused(self):
        real_mount = self.builder.mount_id
        inode = self.artifact.stat().st_ino
        def changed(descriptor):
            observed = real_mount(descriptor)
            return observed + 1 if os.fstat(descriptor).st_ino == inode else observed
        with mock.patch.object(self.builder, "mount_id", side_effect=changed):
            self.refused()

    def test_path_replacement_during_read_is_refused(self):
        real_read = self.builder.os.read
        inode = self.artifact.stat().st_ino
        changed = False
        def reading(descriptor, length):
            nonlocal changed
            data = real_read(descriptor, length)
            if not changed and data and os.fstat(descriptor).st_ino == inode:
                changed = True
                self.artifact.rename(self.base / "preserved-original")
                self.artifact.write_bytes(self.payload)
                self.artifact.chmod(0o555)
            return data
        with mock.patch.object(self.builder.os, "read", side_effect=reading):
            self.refused()
        self.assertTrue(changed)

    def test_checker_uses_private_capture_and_reviewed_digest_before_returning_bytes(self):
        real_run = self.builder.subprocess.run
        commands = []
        def checked(argv, **options):
            commands.append(argv)
            self.assertEqual(argv[:3], [sys.executable, "-I", "-B"])
            self.assertEqual(Path(argv[3]).name, "verify-static-fixture")
            self.assertNotEqual(Path(argv[3]), self.builder.STATIC_VERIFIER)
            self.assertEqual(Path(argv[3]).read_bytes(), self.builder.STATIC_VERIFIER.read_bytes())
            self.assertEqual(argv[4], "--artifact")
            capture = Path(argv[5])
            self.assertNotEqual(capture, self.artifact)
            self.assertEqual(capture.read_bytes(), self.payload)
            self.assertEqual(argv[6:], ["--expected-sha256", self.pin["sha256"]])
            self.assertEqual(options["timeout"], 30)
            self.assertFalse(options.get("shell", False))
            return real_run(argv, **options)
        with mock.patch.object(self.builder.subprocess, "run", side_effect=checked):
            self.assertEqual(self.read(), self.payload)
        self.assertEqual(len(commands), 1)

    def test_static_checker_refusal_malformed_or_wrong_identity_is_refused(self):
        good = self.elf.verify_elf(self.artifact, self.pin["sha256"])
        outputs = [subprocess.CompletedProcess([], 1, stdout="", stderr="injected refusal"),
                   subprocess.CompletedProcess([], 0, stdout="not JSON", stderr="")]
        for field, value in (("status", "FAIL"), ("scope", "wrong"), ("sha256", "0" * 64),
                             ("bytes", len(self.payload) + 1), ("machine", "aarch64")):
            outputs.append(subprocess.CompletedProcess([], 0, stdout=json.dumps(dict(good, **{field: value})), stderr=""))
        for result in outputs:
            with self.subTest(stdout=result.stdout), mock.patch.object(self.builder.subprocess, "run", return_value=result):
                self.refused()

    def test_verifier_timeout_prevents_acceptance(self):
        with mock.patch.object(self.builder.subprocess, "run", side_effect=subprocess.TimeoutExpired("checker", 30)):
            self.refused()

    def test_input_path_is_not_reread_after_verified_bytes_are_captured(self):
        captured = self.builder.read_artifact
        calls = []
        def capture_then_replace(path, pin):
            payload = captured(path, pin)
            calls.append(payload)
            self.write_artifact(bytes(len(self.payload)))
            return payload
        with mock.patch.object(self.builder, "read_artifact", side_effect=capture_then_replace):
            try:
                result = self.builder.build_bundle(self.output, self.artifact)
            except (self.builder.BuildError, OSError) as error:
                self.fail(f"builder discarded captured reviewed bytes and reread changed input: {error}")
        self.assertEqual(calls, [self.payload])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual((self.output / "rootfs/usr/bin/sl-management-fixture").read_bytes(), self.payload)

    def test_static_refusal_prevents_bundle_publication(self):
        with mock.patch.object(self.builder, "read_artifact", side_effect=self.builder.BuildError("injected static refusal")):
            with mock.patch.object(self.builder, "publish") as publish:
                with self.assertRaises(self.builder.BuildError):
                    self.builder.build_bundle(self.output, self.artifact)
                publish.assert_not_called()
        self.assert_no_bundle()


if __name__ == "__main__":
    unittest.main()
