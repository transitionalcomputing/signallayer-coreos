"""Mocked orchestration refusal tests; no Podman, installation or compilation.

These run the controller's actual sequencing with isolated synthetic inputs.
They are not additional native-build evidence or a substitute for ELF tests.
"""
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
LOADER = importlib.machinery.SourceFileLoader("execution_builder", str(ROOT / "tools/build-static-fixture"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
BUILDER = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(BUILDER)
BUILDER_ID = "sha256:" + "7" * 64
SYNTHETIC_BINARY = b"mocked controller output; ELF correctness has separate tests\n"


class ControllerExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.output = self.root / "result"
        self.lock = json.loads((ROOT / "config/static-fixture-toolchain.json").read_bytes())
        self.lock["artifact"] = {"sha256": hashlib.sha256(SYNTHETIC_BINARY).hexdigest(),
                                 "size": len(SYNTHETIC_BINARY)}
        for package in self.lock["packages"]:
            data = ("synthetic cache input " + package["name"]).encode()
            package["sha256"] = hashlib.sha256(data).hexdigest()
            package["size"] = len(data)
            (self.cache / package["filename"]).write_bytes(data)
        for relative in (self.lock["source"]["path"], "tools/static-toolchain/prepare.py",
                         "tools/static-toolchain/Containerfile", "tools/build-static-fixture",
                         "tools/verify-static-fixture"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        self.lock_path = self.root / "config/static-fixture-toolchain.json"
        self.lock_path.parent.mkdir()
        self.write_lock()
        self.info = {"host": {"security": {"rootless": True}}}
        self.base = {"Id": self.lock["base"]["pinnedimage_id"],
                     "Digest": self.lock["base"]["reference"].split("@")[1]}
        self.provenance_change = None
        self.compiled = [SYNTHETIC_BINARY, SYNTHETIC_BINARY]
        self.runtime = subprocess.CompletedProcess([], 0, stdout=b"SignalLayer Candidate C fixture\n", stderr=b"")
        self.run_calls, self.process_calls = [], []
        self.checker = mock.Mock(return_value={"status": "PASS", "scope": "mocked-controller-test"})
        self.compile_calls = []
        self.patches = [mock.patch.object(BUILDER, "ROOT", self.root),
                        mock.patch.object(BUILDER, "LOCK", self.lock_path),
                        mock.patch.object(BUILDER, "PREPARE", self.root / "tools/static-toolchain/prepare.py"),
                        mock.patch.object(BUILDER, "run", side_effect=self.external_run),
                        mock.patch.object(BUILDER.subprocess, "run", side_effect=self.external_process),
                        mock.patch.object(BUILDER, "compile_once", side_effect=self.compile_output),
                        mock.patch.object(BUILDER, "module", return_value=SimpleNamespace(verify_elf=self.checker))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def write_lock(self):
        self.lock_path.write_text(json.dumps(self.lock, sort_keys=True, indent=2) + "\n")

    def external_run(self, argv, **_):
        self.run_calls.append(list(argv))
        stdout = ""
        if argv[1] == "info":
            stdout = json.dumps(self.info)
        elif argv[1:3] == ["image", "inspect"]:
            stdout = json.dumps([self.base])
        elif argv[1] == "build":
            Path(argv[argv.index("--iidfile") + 1]).write_text(BUILDER_ID + "\n")
        elif argv[1] == "cp":
            provenance = {"schema_version": 1, "scope": self.lock["scope"],
                          "lock_sha256": hashlib.sha256(self.lock_path.read_bytes()).hexdigest(),
                          "installed_nevras": self.lock["installed_nevras"],
                          "tool_output": {name: "mocked " + version for name, version in self.lock["versions"].items()}}
            if self.provenance_change:
                self.provenance_change(provenance)
            Path(argv[-1]).write_text(json.dumps(provenance))
        elif argv[1] != "create":
            self.fail("unexpected external controller command: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    def external_process(self, argv, **_):
        self.process_calls.append(list(argv))
        if argv[1] == "rm":
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        self.assertEqual(argv[1], "run")
        if self.lock["base"]["reference"] in argv:
            return self.runtime
        script = argv[-1]
        missing = next(path for path in BUILDER.NEGATIVE_CASES if "rm -- " + path in script)
        token, code, cause = BUILDER.NEGATIVE_CASES[missing]
        stderr = (f"SL_F5_CONTROL_READY:{token}\nSL_F5_CONTROL_REMOVED:{token}\n"
                  f"{cause}\nSL_F5_CONTROL_RESULT:{token}:{code}\n").encode()
        return subprocess.CompletedProcess(argv, code, stdout=b"mocked negative control\n", stderr=stderr)

    def compile_output(self, builder, lock, destination):
        self.compile_calls.append((builder, lock, destination))
        directory = destination / "out"
        directory.mkdir()
        path = directory / BUILDER.BINARY_NAME
        path.write_bytes(self.compiled[len(self.compile_calls) - 1])
        return path

    def invoke(self):
        return BUILDER.build(self.cache, self.output)

    def assert_no_pass(self):
        self.assertFalse((self.output / "result.json").exists(), "failed flow must not publish PASS")

    def test_success_calls_checker_twice_with_reviewed_digest(self):
        report = self.invoke()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(self.compile_calls), 2)
        self.assertEqual(self.checker.call_count, 2)
        self.assertEqual([call.args[1] for call in self.checker.call_args_list],
                         [self.lock["artifact"]["sha256"]] * 2)
        self.assertEqual(report["artifact_sha256"], self.lock["artifact"]["sha256"])

    def test_verifier_uses_reviewed_digest_even_when_rehash_helper_disagrees(self):
        binary = self.root / BUILDER.BINARY_NAME
        binary.write_bytes(SYNTHETIC_BINARY)
        with mock.patch.object(BUILDER, "sha", return_value="0" * 64):
            BUILDER.verify_compilation(binary, self.lock, SimpleNamespace(verify_elf=self.checker))
        self.checker.assert_called_once_with(binary, self.lock["artifact"]["sha256"])

    def test_wrong_reviewed_artifact_digest_refuses_even_identical_outputs(self):
        self.lock["artifact"]["sha256"] = "0" * 64
        self.write_lock()
        with self.assertRaises(BUILDER.BuildError):
            self.invoke()
        self.checker.assert_not_called()
        self.assert_no_pass()

    def test_wrong_reviewed_artifact_size_refuses(self):
        self.lock["artifact"]["size"] += 1
        self.write_lock()
        with self.assertRaises(BUILDER.BuildError):
            self.invoke()
        self.checker.assert_not_called()
        self.assert_no_pass()

    def test_identical_wrong_outputs_do_not_become_their_own_oracle(self):
        self.compiled = [b"x" * len(SYNTHETIC_BINARY)] * 2
        with self.assertRaises(BUILDER.BuildError):
            self.invoke()
        self.checker.assert_not_called()
        self.assert_no_pass()

    def test_divergent_second_output_is_refused(self):
        self.compiled[1] = b"x" * len(SYNTHETIC_BINARY)
        with self.assertRaises(BUILDER.BuildError):
            self.invoke()
        self.assertEqual(self.checker.call_count, 1)
        self.assert_no_pass()

    def test_late_divergent_hashes_fail_reproducibility_guard(self):
        def changed_after_verification(path, expected):
            if "compile-2" in str(path):
                path.write_bytes(b"x" * len(SYNTHETIC_BINARY))
            return {"status": "PASS", "scope": "mocked-controller-test"}

        self.checker.side_effect = changed_after_verification
        with self.assertRaisesRegex(BUILDER.BuildError, "not byte reproducible"):
            self.invoke()
        self.assert_no_pass()

    def test_nonrootless_environment_refuses_before_build(self):
        self.info["host"]["security"]["rootless"] = False
        with self.assertRaisesRegex(BUILDER.BuildError, "rootless"):
            self.invoke()
        self.assertFalse(any(argv[1] == "build" for argv in self.run_calls))
        self.assert_no_pass()

    def test_wrong_base_id_or_digest_refuses_before_build(self):
        original = copy.deepcopy(self.base)
        for field, value in (("Id", "sha256:" + "0" * 64), ("Digest", "sha256:" + "0" * 64)):
            self.base = copy.deepcopy(original)
            self.base[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(BUILDER.BuildError, "base image identity"):
                self.invoke()
            self.assertFalse(any(argv[1] == "build" for argv in self.run_calls))
            self.assert_no_pass()

    def test_provenance_lock_and_inventory_drift_refuse_before_compile(self):
        for field, value in (("lock_sha256", "0" * 64), ("installed_nevras", [])):
            # Each failure writes diagnostics to its own fresh directory.
            self.output = self.root / ("result-" + field)
            self.provenance_change = lambda record, field=field, value=value: record.__setitem__(field, value)
            with self.subTest(field=field), self.assertRaisesRegex(BUILDER.BuildError, "provenance"):
                self.invoke()
            self.assertEqual(self.compile_calls, [])
            self.assert_no_pass()

    def test_malformed_provenance_schema_scope_or_tool_output_refuses(self):
        for field, value in (("schema_version", 2), ("scope", "production"), ("tool_output", {})):
            self.output = self.root / ("result-" + field)
            self.provenance_change = lambda record, field=field, value=value: record.__setitem__(field, value)
            with self.subTest(field=field), self.assertRaises(BUILDER.BuildError):
                self.invoke()
            self.assertEqual(self.compile_calls, [])
            self.assert_no_pass()

    def test_smoke_exit_output_and_stderr_each_block_pass(self):
        for number, (code, stdout, stderr) in enumerate(((1, b"SignalLayer Candidate C fixture\n", b""),
                                                      (0, b"incorrect output\n", b""),
                                                      (0, b"SignalLayer Candidate C fixture\n", b"unexpected diagnostic"))):
            self.output = self.root / ("smoke-" + str(number))
            self.compile_calls = []
            self.runtime = subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)
            with self.subTest(case=number), self.assertRaisesRegex(BUILDER.BuildError, "compatibility smoke"):
                self.invoke()
            self.assert_no_pass()

    def test_orchestration_argv_preserves_fixed_isolation(self):
        self.invoke()
        build = next(argv for argv in self.run_calls if argv[1] == "build")
        for flag in ("--pull=never", "--network=none", "--no-cache", "--isolation=oci"):
            self.assertIn(flag, build)
        runtime = next(argv for argv in self.process_calls
                       if argv[1] == "run" and self.lock["base"]["reference"] in argv)
        for flag in ("--pull=never", "--network=none", "--read-only", "--cap-drop=all"):
            self.assertIn(flag, runtime)
        self.assertEqual(runtime[runtime.index("--user") + 1], "65532:65532")
        self.assertEqual(runtime[runtime.index("--entrypoint") + 1], "/bin/sh")


class CompilationArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.lock = json.loads((ROOT / "config/static-fixture-toolchain.json").read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, malicious=None):
        output = io.BytesIO()
        entries = [("out", None), ("out/" + BUILDER.BINARY_NAME, SYNTHETIC_BINARY)]
        entries += [(name, b"captured diagnostic") for name in
                    ("elf-header.txt", "elf-programs.txt", "elf-dynamic.txt", "symbols.txt", "undefined.txt")]
        if malicious == "extra":
            entries.append(("../escape", b"unlisted"))
        elif malicious == "missing":
            entries.pop()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                if data is None:
                    member.type = tarfile.DIRTYPE
                elif name == "undefined.txt" and malicious in ("symlink", "hardlink", "fifo"):
                    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                   "fifo": tarfile.FIFOTYPE}[malicious]
                    member.linkname = "../../outside"
                    data = None
                else:
                    member.size = len(data)
                archive.addfile(member, None if data is None else io.BytesIO(data))
        return output.getvalue()

    def compile_with(self, payload=None, code=0):
        completed = subprocess.CompletedProcess([], code,
                                                stdout=self.archive() if payload is None else payload,
                                                stderr=b"mocked compiler diagnostic\n")
        with mock.patch.object(BUILDER.subprocess, "run", return_value=completed) as run:
            result = BUILDER.compile_once(BUILDER_ID, self.lock, self.directory)
        return result, run.call_args_list

    def test_compilation_argv_and_source_guards_are_fixed(self):
        result, calls = self.compile_with()
        argv = calls[0].args[0]
        for flag in ("--pull=never", "--network=none", "--read-only", "--cap-drop=all"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/bin/sh")
        self.assertEqual(calls[0].kwargs["input"], (ROOT / self.lock["source"]["path"]).read_bytes())
        script = argv[-1]
        for guard in (self.lock["source"]["sha256"], "sha256sum -c -", "test -f /usr/lib64/libc.a",
                      "command -v rustc", "SL_F5_MISSING_RUSTC", "SL_F5_MISSING_LIBC_STATIC"):
            self.assertIn(guard, script)
        for flag in self.lock["compiler_flags"]:
            self.assertIn(flag, script)
        self.assertEqual(result.read_bytes(), SYNTHETIC_BINARY)

    def test_compilation_failure_keeps_log_and_removes_exact_container(self):
        completed = subprocess.CompletedProcess([], 72, stdout=b"", stderr=b"SL_F5_MISSING_RUSTC\n")
        with mock.patch.object(BUILDER.subprocess, "run", return_value=completed) as run:
            with self.assertRaisesRegex(BUILDER.BuildError, "compilation failed"):
                BUILDER.compile_once(BUILDER_ID, self.lock, self.directory)
        created = run.call_args_list[0].args[0][3]
        self.assertEqual(run.call_args_list[-1].args[0], ["podman", "rm", "-f", created])
        self.assertEqual((self.directory / "compile.log").read_bytes(), completed.stderr)
        self.assertFalse((self.directory / "out").exists())

    def test_malicious_archives_rejected_before_any_extracted_output(self):
        for malicious in ("extra", "missing", "symlink", "hardlink", "fifo"):
            with self.subTest(archive=malicious):
                destination = self.directory / malicious
                destination.mkdir()
                completed = subprocess.CompletedProcess([], 0, stdout=self.archive(malicious), stderr=b"log\n")
                with mock.patch.object(BUILDER.subprocess, "run", return_value=completed):
                    with self.assertRaises(BUILDER.BuildError):
                        BUILDER.compile_once(BUILDER_ID, self.lock, destination)
                self.assertEqual({entry.name for entry in destination.iterdir()}, {"compile.log"},
                                 "archive members must all be checked before extraction")


if __name__ == "__main__":
    unittest.main()
