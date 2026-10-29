#!/usr/bin/env python3
"""Demonstrate offline execution-test sensitivity using disposable source copies.

Every mutation removes an actual development-tool check or changes a constrained
command argument. A kill requires an ordinary unittest assertion failure after
the same targeted test passes unmodified. Syntax/import errors never count.
Neither the real checkout nor its recorded runtime evidence is modified.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
TESTS = Path("tests/podman/static-toolchain")
PREP = "tools/static-toolchain/prepare.py"
BUILD = "tools/build-static-fixture"

# This child runs only mocked execution tests. Block accidental real process or
# network access even if a future mutation/test incorrectly drops its mock.
DRIVER = r'''
import contextlib, importlib.util, io, json, pathlib, sys, unittest
def offline(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.posix_spawnp',
                 'socket.__new__', 'socket.connect', 'socket.bind'):
        raise RuntimeError('offline mutation test attempted real process/network access')
sys.addaudithook(offline)
path, name = pathlib.Path(sys.argv[1]), sys.argv[2]
log = io.StringIO()
with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
    spec = importlib.util.spec_from_file_location('f5_mutation_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromName(name, module)
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures),
                     errors=len(result.errors), skipped=len(result.skipped),
                     successful=result.wasSuccessful(), transcript=log.getvalue()),
                 sort_keys=True))
'''


class MutationError(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def span(source: str, node: ast.AST) -> tuple[int, int]:
    lines = source.splitlines(keepends=True)
    start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
    end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
    return start, end


def function_node(source: str, name: str) -> ast.FunctionDef:
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(nodes) != 1:
        raise MutationError(f"expected one function: {name}")
    return nodes[0]


def replace_once(source: str, function: str, old: str, new: str) -> str:
    begin, end = span(source, function_node(source, function))
    body = source[begin:end]
    if body.count(old) != 1:
        raise MutationError(f"expected one mutation anchor in {function}: {old!r}")
    return source[:begin] + body.replace(old, new, 1) + source[end:]


def disable_guard(source: str, function: str, contains: str) -> str:
    matches = [node.test for node in ast.walk(function_node(source, function))
               if isinstance(node, ast.If)
               and contains in ast.get_source_segment(source, node.test)]
    if len(matches) != 1:
        raise MutationError(f"expected one conditional guard: {contains!r}")
    begin, end = span(source, matches[0])
    return source[:begin] + "False" + source[end:]


def mutations() -> list[dict]:
    prep_class = "PreparationExecutionTests."
    # Builder test names are intentionally explicit: broad test-suite failure
    # elsewhere cannot be mistaken for sensitivity of the nominated gate.
    prep = "test_preparation_execution.py"
    execution = "test_execution.py"
    rows = [
        ("namespace-before-install", PREP, prep, prep_class + "test_namespace_guard_precedes_lock_reads_and_installation",
         "replace", "main", "require_rootless_build_namespace()", "pass"),
        ("base-inventory", PREP, prep, prep_class + "test_base_inventory_drift_prevents_installation_and_evidence",
         "guard", "main", "inventory_digest(before)", None),
        ("postinstall-inventory", PREP, prep, prep_class + "test_postinstall_extra_package_prevents_evidence",
         "guard", "main", 'after != lock["installed_nevras"]', None),
        ("measured-rust-version", PREP, prep, prep_class + "test_measured_rust_version_mismatch_prevents_evidence",
         "replace", "main", 'for name in ("rust", "cargo"):', 'for name in ("cargo",):'),
        ("measured-cargo-version", PREP, prep, prep_class + "test_measured_cargo_version_mismatch_prevents_evidence",
         "replace", "main", 'for name in ("rust", "cargo"):', 'for name in ("rust",):'),
        ("measured-gcc-version", PREP, prep, prep_class + "test_measured_gcc_version_mismatch_prevents_evidence",
         "guard", "main", 'tool_output["gcc"]', None),
        ("measured-binutils-version", PREP, prep, prep_class + "test_measured_binutils_version_mismatch_prevents_evidence",
         "guard", "main", '"GNU ld"', None),
        ("offline-dnf-arguments", PREP, prep, prep_class + "test_exact_offline_install_argv_and_success_evidence",
         "replace", "main", '"--disablerepo=*"', '"--enablerepo=*"'),
    ]
    builder_rows = [
        ("rootless-podman", "ControllerExecutionTests.test_nonrootless_environment_refuses_before_build", "guard", "build", "info.get('host'", None),
        ("base-config-id", "ControllerExecutionTests.test_wrong_base_id_or_digest_refuses_before_build", "replace", "build",
         "image_id(base.get('Id')) != lock['base']['pinnedimage_id']", "False"),
        ("base-manifest-digest", "ControllerExecutionTests.test_wrong_base_id_or_digest_refuses_before_build", "replace", "build",
         "base.get('Digest') != lock['base']['reference'].split('@')[1]", "False"),
        ("provenance-lock", "ControllerExecutionTests.test_provenance_lock_and_inventory_drift_refuse_before_compile", "replace", "validate_preparation",
         "provenance.get('lock_sha256') != hashlib.sha256(lock_bytes).hexdigest()", "False"),
        ("provenance-inventory", "ControllerExecutionTests.test_provenance_lock_and_inventory_drift_refuse_before_compile", "replace", "validate_preparation",
         "provenance.get('installed_nevras') != lock['installed_nevras']", "False"),
        ("two-clean-binary-hashes", "ControllerExecutionTests.test_late_divergent_hashes_fail_reproducibility_guard", "guard", "build", "hashes[0] != hashes[1]", None),
        ("smoke-output", "ControllerExecutionTests.test_smoke_exit_output_and_stderr_each_block_pass", "replace", "build",
         "runtime.stdout != b'SignalLayer Candidate C fixture\\n'", "False"),
        ("smoke-exit", "ControllerExecutionTests.test_smoke_exit_output_and_stderr_each_block_pass", "replace", "build",
         "if runtime.returncode or runtime.stdout", "if 0 or runtime.stdout"),
        ("smoke-stderr", "ControllerExecutionTests.test_smoke_exit_output_and_stderr_each_block_pass", "replace", "build", "or runtime.stderr:", "or False:"),
        ("compile-isolation-argv", "CompilationArchiveTests.test_compilation_argv_and_source_guards_are_fixed", "replace", "compile_once", "'--network=none'", "'--network=host'"),
        ("archive-member-set", "CompilationArchiveTests.test_malicious_archives_rejected_before_any_extracted_output", "guard", "compile_once", "len(members)!=len(expected)", None),
        ("elf-checker-execution", "ControllerExecutionTests.test_success_calls_checker_twice_with_reviewed_digest", "replace", "verify_compilation", "elf.verify_elf(binary, lock['artifact']['sha256'])", "{}"),
        ("reviewed-artifact-size", "ControllerExecutionTests.test_wrong_reviewed_artifact_size_refuses", "guard", "verify_compilation", "len(data) != lock['artifact']['size']", None),
        ("reviewed-artifact-digest", "ControllerExecutionTests.test_wrong_reviewed_artifact_digest_refuses_even_identical_outputs", "guard", "verify_compilation", "hashlib.sha256(data).hexdigest() != lock['artifact']['sha256']", None),
        ("explicit-oci-build-isolation", "ControllerExecutionTests.test_orchestration_argv_preserves_fixed_isolation", "replace", "build", "'--isolation=oci'", "'--isolation=chroot'"),
        ("reviewed-oracle-substitution", "ControllerExecutionTests.test_verifier_uses_reviewed_digest_even_when_rehash_helper_disagrees", "replace", "verify_compilation",
         "elf.verify_elf(binary, lock['artifact']['sha256'])", "elf.verify_elf(binary, sha(binary))"),
        ("compile-source-checksum-guard", "CompilationArchiveTests.test_compilation_argv_and_source_guards_are_fixed", "replace", "compile_script", "| sha256sum -c -", "| cat >/dev/null"),
        ("compile-static-library-guard", "CompilationArchiveTests.test_compilation_argv_and_source_guards_are_fixed", "replace", "compile_script", "test -f /usr/lib64/libc.a", "true"),
        ("archive-type-prevalidation", "CompilationArchiveTests.test_malicious_archives_rejected_before_any_extracted_output", "guard", "compile_once", "name != 'out' and member.isfile()", None),
    ]
    for gate, test, kind, function, old, new in builder_rows:
        rows.append((gate, BUILD, execution, test,
                     kind, function, old, new))
    result = [dict(zip(("gate", "source", "test_file", "test", "kind", "function", "old", "new"), row))
              for row in rows]
    extra = {"smoke-stderr", "compile-source-checksum-guard",
             "compile-static-library-guard", "archive-type-prevalidation"}
    c1 = {"reviewed-artifact-size", "reviewed-artifact-digest", "reviewed-oracle-substitution"}
    for row in result:
        row["category"] = ("C1-reviewed-binary-oracle" if row["gate"] in c1 else
                           "R3-explicit-builder-isolation" if row["gate"] == "explicit-oci-build-isolation" else
                           "additional-execution-control" if row["gate"] in extra else
                           "C2-original-19-execution-gates")
    return result


def copy_inputs(destination: Path) -> None:
    for name in ("tools", "config", "management-fixture", str(TESTS)):
        source, target = ROOT / name, destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    name = "docs/development/0.0.4-phase1-pass3-installed-nevras.txt"
    target = destination / name
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / name, target)


def targeted(root: Path, row: dict) -> dict:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    value = subprocess.run([sys.executable, "-B", "-c", DRIVER,
                            str(root / TESTS / row["test_file"]), row["test"]],
                           cwd=root, env=env, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30, check=False)
    if value.returncode:
        return dict(tests=0, failures=0, errors=1, skipped=0, successful=False,
                    transcript=value.stdout + value.stderr, driver_exit=value.returncode)
    try:
        return json.loads(value.stdout)
    except ValueError:
        return dict(tests=0, failures=0, errors=1, skipped=0, successful=False,
                    transcript=value.stdout + value.stderr, driver_exit=value.returncode)


def run_mutations(output: Path) -> dict:
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise MutationError("require a new report path with an existing parent")
    rows = mutations()
    fingerprinted = (PREP, BUILD, str(TESTS / "run-mutations.py"),
                     str(TESTS / "test_execution.py"),
                     str(TESTS / "test_preparation_execution.py"),
                     "config/static-fixture-toolchain.json",
                     "management-fixture/src/main.rs")
    original = {name: sha((ROOT / name).read_bytes()) for name in fingerprinted}
    results = []
    with tempfile.TemporaryDirectory(prefix="sl-f5-mutations-") as temporary:
        root = Path(temporary) / "source"
        root.mkdir()
        copy_inputs(root)
        for row in rows:
            path = root / row["source"]
            source = path.read_text()
            baseline = targeted(root, row)
            record = dict(gate=row["gate"], source=row["source"],
                          category=row["category"],
                          test_file=row["test_file"], test=row["test"],
                          baseline=baseline, source_sha256=sha(source.encode()),
                          mutation=dict(kind=row["kind"], function=row["function"],
                                        anchor=row["old"], replacement=("False" if row["kind"] == "guard" else row["new"])))
            if baseline.get("tests") != 1 or not baseline.get("successful") or baseline.get("skipped"):
                record["status"] = "BASELINE_INVALID"
                results.append(record)
                continue
            try:
                changed = (disable_guard(source, row["function"], row["old"])
                           if row["kind"] == "guard"
                           else replace_once(source, row["function"], row["old"], row["new"]))
                ast.parse(changed)
                path.write_text(changed)
                mutated = targeted(root, row)
                killed = (mutated.get("tests") == 1 and mutated.get("failures", 0) > 0
                          and mutated.get("errors") == 0 and mutated.get("skipped") == 0)
                record.update(mutated=mutated, mutated_sha256=sha(changed.encode()),
                              status="KILLED" if killed else "SURVIVED_OR_INVALID")
            except (MutationError, SyntaxError) as error:
                record.update(status="MUTATION_INVALID", error=str(error))
            finally:
                path.write_text(source)
            results.append(record)
    unchanged = all(sha((ROOT / name).read_bytes()) == value for name, value in original.items())
    categories = {name: sum(row["category"] == name for row in rows)
                  for name in sorted({row["category"] for row in rows})}
    report = dict(schema_version=1, scope="offline-mocked-execution-gate-sensitivity-only",
                  source_sha256=original, source_checkout_unchanged=unchanged,
                  categories=categories,
                  gates=len(results), killed=sum(r["status"] == "KILLED" for r in results),
                  status="PASS" if unchanged and all(r["status"] == "KILLED" for r in results) else "FAIL",
                  runtime_or_native_build_evidence_replaced=False, results=results)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_mutations(args.output.absolute())
    except (MutationError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"offline mutation proof refused: {error}\n")
    print(json.dumps({key: result[key] for key in ("status", "gates", "killed", "source_checkout_unchanged")}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
