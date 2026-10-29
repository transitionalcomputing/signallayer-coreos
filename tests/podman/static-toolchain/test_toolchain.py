"""Offline lock/cache refusal tests. No package installation or image build."""
import copy
import hashlib
import io
import tarfile
import subprocess
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("static_preparation", ROOT / "tools/static-toolchain/prepare.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
LOCK_PATH = ROOT / "config/static-fixture-toolchain.json"
BUILD_LOADER = importlib.machinery.SourceFileLoader("static_builder", str(ROOT / "tools/build-static-fixture"))
BUILD_SPEC = importlib.util.spec_from_loader(BUILD_LOADER.name, BUILD_LOADER)
BUILDER = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_LOADER.exec_module(BUILDER)


class ToolchainLockTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(LOCK_PATH.read_bytes())

    def rejected(self, change, reason=None):
        lock = copy.deepcopy(self.lock)
        change(lock)
        with self.assertRaises(PREP.PreparationError) as captured:
            PREP.validate_lock(lock)
        if reason:
            self.assertRegex(str(captured.exception), reason)

    def test_reviewed_real_lock_is_valid(self):
        PREP.validate_lock(self.lock)
        self.assertEqual(len(self.lock["packages"]), 23)
        self.assertEqual(self.lock["scope"], "development-only-static-toolchain")

    def test_wrong_schema_scope_base_target_are_rejected(self):
        for field, value in (("schema_version", 2), ("scope", "production"), ("target", "aarch64-linux-gnu")):
            with self.subTest(field=field):
                self.rejected(lambda lock: lock.__setitem__(field, value))
        self.rejected(lambda lock: lock["base"].__setitem__("reference", "fedora:latest"), "immutable base")

    def test_base_and_package_body_hashes_are_mandatory(self):
        self.rejected(lambda lock: lock["base"].pop("pinnedimage_id"), "image ID")
        self.rejected(lambda lock: lock["base"].__setitem__("installed_nevras_sha256", "bad"), "inventory digest")
        self.rejected(lambda lock: lock["packages"][0].pop("sha256"), "RPM digest")
        self.rejected(lambda lock: lock["packages"][0].__setitem__("size", 0), "RPM size")

    def test_repo_metadata_hash_and_https_provenance_are_mandatory(self):
        self.rejected(lambda lock: lock["repositories"][0].pop("repomd_sha256"), "metadata digest")
        self.rejected(lambda lock: lock["repositories"][0].pop("url"), "HTTPS")
        self.rejected(lambda lock: lock["packages"][0].__setitem__("url", "http://invalid/rpm"), "HTTPS")
        self.rejected(lambda lock: lock["packages"][0].__setitem__("repo_id", "unlisted"), "repository")

    def test_wrong_or_absent_fedora_signing_key_is_rejected(self):
        self.rejected(lambda lock: lock.__setitem__("signing_key_fingerprint", "0" * 40), "signing")
        self.rejected(lambda lock: lock.pop("signing_key_fingerprint"), "signing")

    def test_signing_key_path_and_file_digest_are_required(self):
        self.rejected(lambda lock: lock.pop("signing_key_path"), "key|signing")
        self.rejected(lambda lock: lock.__setitem__("signing_key_path", "/tmp/untrusted-key"), "key|signing")
        self.rejected(lambda lock: lock.pop("signing_key_sha256"), "key|signing")
        self.rejected(lambda lock: lock.__setitem__("signing_key_sha256", "bad"), "key|signing")

    def test_floating_nevra_and_version_are_rejected(self):
        self.rejected(lambda lock: lock["packages"][0].__setitem__("nevra", "binutils-latest"))
        self.rejected(lambda lock: lock["versions"].__setitem__("rust", "latest"), "numeric")

    def test_missing_source_sha_or_compiler_flags_are_rejected(self):
        self.rejected(lambda lock: lock["source"].pop("sha256"), "source identity")
        self.rejected(lambda lock: lock["source"].__setitem__("path", "attacker.rs"), "source identity")
        self.rejected(lambda lock: lock.__setitem__("compiler_flags", []), "compiler flags")

    def test_nonfixed_dynamic_or_extra_compiler_flags_are_rejected(self):
        self.rejected(lambda lock: lock["compiler_flags"].append("-Clink-arg=-ldl"), "compiler flags")
        self.rejected(lambda lock: lock["compiler_flags"].remove("-Ctarget-feature=+crt-static"), "compiler flags")

    def test_missing_compiler_or_static_library_is_rejected(self):
        for name in ("rust", "cargo", "gcc", "binutils", "glibc-static", "glibc-devel", "rust-std-static"):
            with self.subTest(package=name):
                self.rejected(lambda lock: lock.__setitem__("packages", [
                    package for package in lock["packages"] if package["name"] != name]),
                    "missing compiler/static library")

    def test_glibc_static_must_match_the_isolated_builder_glibc(self):
        def drift(lock):
            package = next(item for item in lock["packages"] if item["name"] == "glibc-static")
            old = package["nevra"]
            package["nevra"] = "glibc-static-0:2.43-8.fc44.x86_64"
            lock["installed_nevras"] = sorted(package["nevra"] if value == old else value
                                               for value in lock["installed_nevras"])
        self.rejected(drift, "glibc/static/devel version mismatch")

    def test_exact_tool_version_must_match_package_version(self):
        for name in ("rust", "cargo", "gcc", "binutils"):
            with self.subTest(tool=name):
                self.rejected(lambda lock: lock["versions"].__setitem__(name, "0.0.0"),
                              "package/version mismatch")

    def test_floating_nevra_remains_invalid_when_listed_in_final_closure(self):
        def drift(lock):
            package = lock["packages"][0]
            old = package["nevra"]
            package["nevra"] = package["name"] + "-latest"
            lock["installed_nevras"] = sorted(package["nevra"] if value == old else value
                                               for value in lock["installed_nevras"])
        self.rejected(drift, "floating or malformed exact NEVRA")

    def test_package_must_appear_in_final_closure(self):
        package_nevra = self.lock["packages"][0]["nevra"]
        self.rejected(lambda lock: lock["installed_nevras"].remove(package_nevra), "installed closure")

    def test_duplicate_package_and_unlisted_final_nevra_are_rejected(self):
        self.rejected(lambda lock: lock["packages"].append(copy.deepcopy(lock["packages"][0])), "duplicate")
        self.rejected(lambda lock: lock["installed_nevras"].append(lock["installed_nevras"][0]), "sorted unique")

    def test_path_traversal_rpm_filename_is_rejected(self):
        self.rejected(lambda lock: lock["packages"][0].__setitem__("filename", "../escape.rpm"), "filename")

    def test_duplicate_json_key_is_rejected(self):
        with self.assertRaisesRegex(PREP.PreparationError, "duplicate JSON key"):
            json.loads('{"scope": "first", "scope": "second"}', object_pairs_hook=PREP.reject_duplicate_keys)

    def test_host_path_refuses_even_when_effective_root(self):
        with mock.patch.object(PREP.os, "geteuid", return_value=0), mock.patch.object(PREP, "run") as run:
            with self.assertRaisesRegex(PREP.PreparationError, "isolated OCI build"):
                PREP.require_rootless_build_namespace()
            run.assert_not_called()

    def test_mapping_host_root_is_refused(self):
        with mock.patch.object(PREP, "__file__", "/build/prepare.py"), \
                mock.patch.object(PREP.os, "geteuid", return_value=0), \
                mock.patch.object(Path, "read_text", return_value="0 0 4294967295\n"):
            with self.assertRaisesRegex(PREP.PreparationError, "unprivileged host identity|host root"):
                PREP.require_rootless_build_namespace()

    def test_rootless_identity_mappings_are_accepted_as_unit_fixture_only(self):
        with mock.patch.object(PREP, "__file__", "/build/prepare.py"), \
                mock.patch.object(PREP.os, "geteuid", return_value=0), \
                mock.patch.object(Path, "read_text", return_value="0 1000 1\n1 100000 65536\n"):
            PREP.require_rootless_build_namespace()


class KeyInventoryAccountingTests(unittest.TestCase):
    def test_pinned_key_bootstrap_record_is_required_in_expected_inventory(self):
        lock=json.loads(LOCK_PATH.read_bytes())
        lock['installed_nevras'].remove(lock['signing_key_nevra'])
        with self.assertRaisesRegex(PREP.PreparationError,'key bootstrap'):
            PREP.validate_lock(lock)


class OfflineRPMCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.build = Path(self.temp.name)
        self.cache = self.build / "rpms"
        self.cache.mkdir()
        self.data = b"synthetic RPM cache fixture; never installed\n"
        self.package = {"filename": "fixture-1-1.x86_64.rpm", "name": "fixture",
                        "nevra": "fixture-0:1-1.x86_64", "size": len(self.data),
                        "sha256": hashlib.sha256(self.data).hexdigest()}
        self.path = self.cache / self.package["filename"]
        self.path.write_bytes(self.data)
        self.lock = {"packages": [self.package], "signing_key_fingerprint":
                     json.loads(LOCK_PATH.read_bytes())["signing_key_fingerprint"]}
        self.patch = mock.patch.object(PREP, "BUILD", self.build)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def rpm_query(self, argv, **_):
        self.assertIn(argv[0], ("rpm", "rpmkeys"), "cache checks must not install packages")
        if argv[0] == "rpm":
            self.assertIn("-qp", argv)
            return self.package["name"] + "\n" + self.package["nevra"] + "\n"
        self.assertIn("--checksig", argv)
        return (str(self.path) + ": digests signatures OK\nSignature fingerprint "
                + self.lock["signing_key_fingerprint"] + "\n")

    def test_exact_verified_cache_is_accepted_without_installing(self):
        with mock.patch.object(PREP, "run", side_effect=self.rpm_query):
            paths, signatures = PREP.verify_rpms(self.lock)
        self.assertEqual(paths, [str(self.path)])
        self.assertEqual(set(signatures), {self.path.name})

    def test_corrupted_bytes_and_size_fail_before_any_rpm_command(self):
        for data in (self.data + b"changed", bytes(len(self.data))):
            self.path.write_bytes(data)
            with self.subTest(data=data), mock.patch.object(PREP, "run") as run:
                with self.assertRaisesRegex(PREP.PreparationError, "size/digest mismatch"):
                    PREP.verify_rpms(self.lock)
                run.assert_not_called()

    def test_unlisted_or_missing_cached_rpm_fails(self):
        extra = self.cache / "extra.rpm"
        extra.write_bytes(b"unlisted")
        with self.assertRaisesRegex(PREP.PreparationError, "exactly the locked filenames"):
            PREP.verify_rpms(self.lock)
        extra.unlink()
        self.path.unlink()
        with self.assertRaisesRegex(PREP.PreparationError, "exactly the locked filenames"):
            PREP.verify_rpms(self.lock)

    def test_symlink_rpm_is_not_followed(self):
        self.path.unlink()
        source = self.build / "external.rpm"
        source.write_bytes(self.data)
        self.path.symlink_to(source)
        with mock.patch.object(PREP, "run") as run:
            with self.assertRaises((PREP.PreparationError, OSError)):
                PREP.verify_rpms(self.lock)
            run.assert_not_called()

    def test_wrong_rpm_identity_is_rejected(self):
        with mock.patch.object(PREP, "run", return_value="different\nfixture-0:1-1.x86_64\n"):
            with self.assertRaisesRegex(PREP.PreparationError, "metadata mismatch"):
                PREP.verify_rpms(self.lock)

    def test_untrusted_bad_or_missing_rpm_signature_is_rejected(self):
        for response in ("digests OK", "digests signatures NOKEY", "digests signatures NOT OK",
                         "digests signatures OK BAD"):
            def query(argv, **_):
                if argv[0] == "rpm":
                    return self.rpm_query(argv)
                return response
            with self.subTest(response=response), mock.patch.object(PREP, "run", side_effect=query):
                with self.assertRaisesRegex(PREP.PreparationError, "signature not verified"):
                    PREP.verify_rpms(self.lock)

    def test_signature_ok_from_another_key_is_not_sufficient(self):
        def query(argv, **_):
            if argv[0] == "rpm":
                return self.rpm_query(argv)
            if "-v" in argv:
                return "Signature fingerprint " + "0" * 40 + " OK\n"
            return self.rpm_query(argv)
        with mock.patch.object(PREP, "run", side_effect=query):
            with self.assertRaisesRegex(PREP.PreparationError, "signing key|signature"):
                PREP.verify_rpms(self.lock)


class DisposableSigningKeyTests(unittest.TestCase):
    """Mocked RPM6 keyring bootstrap; never imports into any actual keyring."""
    def setUp(self):
        self.lock = json.loads(LOCK_PATH.read_bytes())
        self.key = b"synthetic signing-key fixture; not a real public key\n"
        # Bootstrap behavior is isolated from the separately tested reviewed
        # lock. Synthetic bytes cannot stand in for measured Fedora key bytes.
        self.fixture_lock = copy.deepcopy(self.lock)
        self.fixture_lock["signing_key_sha256"] = hashlib.sha256(self.key).hexdigest()

    def test_matching_pinned_file_is_imported_then_fingerprint_checked(self):
        fingerprint = self.fixture_lock["signing_key_fingerprint"]
        with mock.patch.object(PREP, "regular_bytes", return_value=self.key) as read, \
                mock.patch.object(PREP, "run", side_effect=["", fingerprint + "\n"]) as run:
            PREP.initialize_signing_key(self.fixture_lock)
        read.assert_called_once_with(Path(self.fixture_lock["signing_key_path"]))
        self.assertEqual(run.call_args_list, [
            mock.call(["rpmkeys", "--import", self.fixture_lock["signing_key_path"]]),
            mock.call(["rpmkeys", "--list"]),
        ])

    def test_changed_key_file_refuses_before_import(self):
        with mock.patch.object(PREP, "regular_bytes", return_value=b"changed key"), \
                mock.patch.object(PREP, "run") as run:
            with self.assertRaisesRegex(PREP.PreparationError, "signing|key|digest"):
                PREP.initialize_signing_key(self.lock)
            run.assert_not_called()

    def test_imported_keyring_without_pinned_fingerprint_refuses(self):
        with mock.patch.object(PREP, "regular_bytes", return_value=self.key), \
                mock.patch.object(PREP, "run", side_effect=["", "0" * 40 + "\n"]):
            with self.assertRaisesRegex(PREP.PreparationError, "signing|key|fingerprint"):
                PREP.initialize_signing_key(self.fixture_lock)


class ImmutableImageIDTests(unittest.TestCase):
    def test_bare_podman_image_id_is_canonicalized(self):
        self.assertEqual(BUILDER.image_id('a'*64),'sha256:'+'a'*64)

    def test_prefixed_podman_image_id_is_preserved(self):
        self.assertEqual(BUILDER.image_id('sha256:'+'a'*64),'sha256:'+'a'*64)

    def test_invalid_or_floating_image_id_is_rejected(self):
        for value in (None,'latest','repo:tag','sha256:'+'a'*63,'sha512:'+'a'*64):
            with self.subTest(value=value), self.assertRaises(BUILDER.BuildError):
                BUILDER.image_id(value)


class MissingInputControlTests(unittest.TestCase):
    """Synthetic refusal controls, distinct from the native deleted-file runs."""
    def result(self, missing, returncode=None, stderr=None):
        token, code, cause = BUILDER.NEGATIVE_CASES[missing]
        if stderr is None:
            stderr = '\n'.join([f'SL_F5_CONTROL_READY:{token}', f'SL_F5_CONTROL_REMOVED:{token}',
                                cause, f'SL_F5_CONTROL_RESULT:{token}:{code}', '']).encode()
        return subprocess.CompletedProcess([], code if returncode is None else returncode,
                                           stdout=b'fixture source: OK\n', stderr=stderr)

    def test_both_exact_missing_input_causes_are_accepted(self):
        for missing in BUILDER.NEGATIVE_CASES:
            with self.subTest(missing=missing):
                report = BUILDER.validate_negative_control(missing, self.result(missing))
                self.assertEqual(report['status'], 'EXPECTED_FAILURE')
                self.assertEqual(report['missing'], missing)

    def test_infrastructure_or_unrelated_failure_is_not_a_passing_control(self):
        missing = '/usr/bin/rustc'
        for code in (0, 1, 125, 126, 127, -9):
            with self.subTest(exit=code), self.assertRaisesRegex(BUILDER.BuildError, 'missing-input failure evidence'):
                BUILDER.validate_negative_control(missing, self.result(missing, returncode=code))
        with self.assertRaises(BUILDER.BuildError):
            BUILDER.validate_negative_control(missing, self.result(missing, stderr=b'Error: storage unavailable\n'))

    def test_missing_duplicate_reordered_or_wrong_cause_witnesses_fail(self):
        missing = '/usr/bin/rustc'
        lines = self.result(missing).stderr.decode().splitlines()
        variants = [lines[:index] + lines[index + 1:] for index in range(len(lines))]
        variants += [lines + [lines[0]], list(reversed(lines)),
                     [line.replace('SL_F5_MISSING_RUSTC', 'SL_F5_MISSING_LIBC_STATIC') for line in lines]]
        for index, variant in enumerate(variants):
            with self.subTest(case=index), self.assertRaises(BUILDER.BuildError):
                BUILDER.validate_negative_control(missing, self.result(missing, stderr=('\n'.join(variant)+'\n').encode()))

    def test_only_the_two_fixed_missing_paths_are_authorized(self):
        lock=json.loads(LOCK_PATH.read_bytes())
        with self.assertRaisesRegex(BUILDER.BuildError, 'unreviewed'):
            BUILDER.negative_script(lock, '/usr/bin/other')
        with self.assertRaisesRegex(BUILDER.BuildError, 'unreviewed'):
            BUILDER.validate_negative_control('/etc/passwd', self.result('/usr/bin/rustc'))


class StaticBuilderInputTests(unittest.TestCase):
    """Synthetic byte cache only; never RPM parsing, installation or compilation."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.lock = json.loads(LOCK_PATH.read_bytes())
        source = self.root / self.lock["source"]["path"]
        source.parent.mkdir(parents=True)
        source.write_bytes((ROOT / self.lock["source"]["path"]).read_bytes())
        for item in self.lock["packages"]:
            data = b"not a real RPM: synthetic cache fixture " + item["name"].encode()
            item["sha256"] = hashlib.sha256(data).hexdigest()
            item["size"] = len(data)
            (self.cache / item["filename"]).write_bytes(data)
        self.patch = mock.patch.object(BUILDER, "ROOT", self.root)
        self.patch.start()

    def test_compile_cleanup_keeps_generated_container_identity(self):
        payload=io.BytesIO()
        names={'out':None,'out/sl-management-fixture':b'fixture','elf-header.txt':b'',
               'elf-programs.txt':b'','elf-dynamic.txt':b'','symbols.txt':b'','undefined.txt':b''}
        with tarfile.open(fileobj=payload,mode='w') as archive:
            for name,data in names.items():
                member=tarfile.TarInfo(name)
                if data is None:member.type=tarfile.DIRTYPE;archive.addfile(member)
                else:member.size=len(data);archive.addfile(member,io.BytesIO(data))
        destination=self.root/'compilation';destination.mkdir()
        completed=subprocess.CompletedProcess([],0,stdout=payload.getvalue(),stderr=b'')
        with mock.patch.object(BUILDER.subprocess,'run',return_value=completed) as run:
            BUILDER.compile_once('sha256:'+'1'*64,self.lock,destination)
        created=run.call_args_list[0].args[0][3]
        self.assertTrue(created.startswith('sl-f5-compile-'))
        self.assertEqual(run.call_args_list[-1].args[0],['podman','rm','-f',created])

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_matching_source_and_synthetic_cache_pass_only_input_comparison(self):
        BUILDER.validate_inputs(self.lock, self.cache)

    def test_source_byte_drift_is_rejected_before_any_external_command(self):
        (self.root / self.lock["source"]["path"]).write_bytes(b"unauthorized source")
        with mock.patch.object(BUILDER, "run") as run:
            with self.assertRaisesRegex(BUILDER.BuildError, "source hash drift"):
                BUILDER.validate_inputs(self.lock, self.cache)
            run.assert_not_called()

    def test_source_symlink_is_not_followed(self):
        source = self.root / self.lock["source"]["path"]
        real = self.root / "source.rs"
        source.rename(real)
        source.symlink_to(real)
        with self.assertRaises(OSError):
            BUILDER.validate_inputs(self.lock, self.cache)

    def test_changed_cached_rpm_bytes_are_rejected(self):
        path = self.cache / self.lock["packages"][0]["filename"]
        original = path.read_bytes()
        for data in (bytes(len(original)), original + b"drift"):
            path.write_bytes(data)
            with self.assertRaisesRegex(BUILDER.BuildError, "RPM cache size/hash drift"):
                BUILDER.validate_inputs(self.lock, self.cache)

    def test_missing_or_extra_cached_input_is_rejected(self):
        path = self.cache / self.lock["packages"][0]["filename"]
        path.unlink()
        with self.assertRaisesRegex(BUILDER.BuildError, "unlisted or missing"):
            BUILDER.validate_inputs(self.lock, self.cache)
        path.write_bytes(b"wrong")
        (self.cache / "unlisted.rpm").write_bytes(b"extra")
        with self.assertRaisesRegex(BUILDER.BuildError, "unlisted or missing"):
            BUILDER.validate_inputs(self.lock, self.cache)

    def test_cached_rpm_symlink_is_rejected(self):
        path = self.cache / self.lock["packages"][0]["filename"]
        real = self.root / "external.rpm"
        path.rename(real)
        path.symlink_to(real)
        with self.assertRaisesRegex(BUILDER.BuildError, "RPM cache size/hash drift"):
            BUILDER.validate_inputs(self.lock, self.cache)

    def test_output_allows_only_the_fixed_regular_artifact(self):
        directory = self.root / "out"
        directory.mkdir()
        fixed = directory / BUILDER.BINARY_NAME
        fixed.write_bytes(b"synthetic; not executable")
        self.assertEqual(BUILDER.validate_output(directory), fixed)
        for name in (".hidden", "extra.so", "loader"):
            extra = directory / name
            extra.write_bytes(b"extra")
            with self.assertRaisesRegex(BUILDER.BuildError, "unlisted or missing compiled output"):
                BUILDER.validate_output(directory)
            extra.unlink()
        fixed.unlink()
        with self.assertRaisesRegex(BUILDER.BuildError, "unlisted or missing compiled output"):
            BUILDER.validate_output(directory)

    def test_fixed_output_symlink_or_directory_is_rejected(self):
        directory = self.root / "out"
        directory.mkdir()
        fixed = directory / BUILDER.BINARY_NAME
        fixed.symlink_to(self.root / "external")
        with self.assertRaisesRegex(BUILDER.BuildError, "not a regular file"):
            BUILDER.validate_output(directory)
        fixed.unlink()
        fixed.mkdir()
        with self.assertRaisesRegex(BUILDER.BuildError, "not a regular file"):
            BUILDER.validate_output(directory)


if __name__ == "__main__":
    unittest.main()
