#!/usr/bin/env python3
"""Strict source-copy mutation controls for W1; never build or run OS images.

A guard is detected only by an ordinary assertion failure in its named test.
Errors, import/syntax failures, skips and failed unmodified controls are not
evidence of detection. Linux fd gates remain BLOCKED on other platforms.
"""

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
BUILDER = Path("tools/build-management-rootfs")
PORTABLE = "test_binary_input.CapturedArtifactControlTests."
LINUX = "test_binary_input.BinaryInputFixtures."

# name, test, function, AST node kind, exact condition fragment(s), requires Linux.
GATES = [
    ("artifact-digest", PORTABLE + "test_same_size_wrong_capture_fails_before_checker",
     "read_artifact", "if", ("digest(data) != pin['sha256']",), False),
    ("artifact-size", PORTABLE + "test_wrong_capture_size_fails_before_checker",
     "read_artifact", "if", ("len(data) != pin['size']",), False),
    ("checker-source-pin", PORTABLE + "test_changed_checker_source_is_not_executed",
     "read_artifact", "if", ("digest(checker) != pin['verifier_sha256']",), False),
    ("lock-contract-binding", PORTABLE + "test_lock_drift_is_not_self_approved",
     "reviewed_artifact", "compare", ("inputs['config/static-fixture-toolchain.json'] != digest(lock_bytes)",), False),
    ("source-bindings", PORTABLE + "test_source_drift_does_not_authorize_the_same_binary",
     "reviewed_artifact", "compare", ("inputs['management-fixture/src/main.rs'] !=", "lock['source'] !="), False),
    ("target-binding", PORTABLE + "test_wrong_target_is_rejected_even_with_coherent_test_lock_hash",
     "reviewed_artifact", "compare", ("lock['target'] != 'x86_64-unknown-linux-gnu'",), False),
    ("reviewed-pin-shape", PORTABLE + "test_malformed_or_unbounded_reviewed_pin_is_rejected",
     "reviewed_artifact", "if", ("set(pin) !=",), False),
    ("checker-report-identity", PORTABLE + "test_wrong_checker_identity_is_refused",
     "read_artifact", "if", ("report.get('status') != 'PASS'",), False),
    ("checker-reviewed-argument", PORTABLE + "test_private_checker_capture_gets_the_reviewed_hash_and_exact_bytes",
     "read_artifact", "digest-argument", (), False),
    ("independent-checker-call", PORTABLE + "test_private_checker_capture_gets_the_reviewed_hash_and_exact_bytes",
     "read_artifact", "checker-call", (), False),
    ("checker-timeout", PORTABLE + "test_private_checker_capture_gets_the_reviewed_hash_and_exact_bytes",
     "read_artifact", "timeout", (), False),
    ("fixed-executable-mode", PORTABLE + "test_manifest_cannot_change_the_fixed_executable_destination_or_mode",
     "expected_manifest", "if", ("name != ARTIFACT_DESTINATION or mode != 365",), False),
    ("mandatory-executable-entry", PORTABLE + "test_manifest_refuses_omission_of_the_fixed_executable",
     "expected_manifest", "if", ("fixture is None",), False),
    ("input-alias", LINUX + "test_external_hardlink_alias_is_refused",
     "regular_snapshot", "if", ("not stat.S_ISREG(info.st_mode) or info.st_nlink != 1",), True),
    ("input-special-modes", LINUX + "test_special_permission_bits_are_refused",
     "regular_snapshot", "if", ("info.st_mode & 3584",), True),
    ("input-parent-mode", LINUX + "test_group_or_world_writable_input_parent_is_refused",
     "regular_snapshot", "if", ("artifact and os.fstat(parent_fd).st_mode & 18",), True),
    ("input-xattrs", LINUX + "test_capabilities_acl_and_other_unreviewed_xattrs_are_refused",
     "regular_snapshot", "if", ("any((x != 'security.selinux'",), True),
    ("input-fd-mount-binding", LINUX + "test_mount_identity_substitution_is_refused",
     "regular_snapshot", "if", ("mount_id(fd) != mount_id(parent_fd)",), True),
    ("input-read-revalidation", LINUX + "test_content_change_during_read_is_refused",
     "regular_snapshot", "if", ("size != info.st_size or stamp(os.fstat(fd))",), True),
    ("mandatory-artifact-validation", LINUX + "test_static_refusal_prevents_bundle_publication",
     "build_bundle", "artifact-call", (), True),
    ("captured-binary-copy", LINUX + "test_input_path_is_not_reread_after_verified_bytes_are_captured",
     "build_bundle", "captured-copy", (), True),
    ("mandatory-staged-verification", "test_rootfs.RootfsFixtures.test_external_verifier_refusal_never_publishes",
     "build_bundle", "staged-call", (), True),
]


def isolated_copy(destination):
    for relative in ("tools/build-management-rootfs", "tools/verify-management-rootfs",
                     "tools/verify-static-fixture", "config/static-fixture-toolchain.json",
                     "config/static-fixture-toolchain.contract.json",
                     "tests/podman/rootfs/test_rootfs.py", "tests/podman/rootfs/test_binary_input.py",
                     "tests/podman/rootfs/expected-source-identity.json"):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    shutil.copytree(ROOT / "management-fixture", destination / "management-fixture")


def mutation(source, gate):
    _, _, function, kind, fragments, _ = gate
    tree = ast.parse(source)
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function]
    if len(selected) != 1:
        raise ValueError("mutation function missing/ambiguous: " + function)
    counts = [0] * max(1, len(fragments))

    class Mutator(ast.NodeTransformer):
        def visit_If(self, node):
            if kind == "if" and fragments[0] in ast.unparse(node.test):
                counts[0] += 1
                node.test = ast.Constant(False)
                return node
            return self.generic_visit(node)

        def visit_Compare(self, node):
            if kind == "compare":
                expression = ast.unparse(node)
                for index, fragment in enumerate(fragments):
                    if fragment in expression:
                        counts[index] += 1
                        return ast.Constant(False)
            return self.generic_visit(node)

        def visit_List(self, node):
            if kind == "digest-argument":
                for index, element in enumerate(node.elts[:-1]):
                    if isinstance(element, ast.Constant) and element.value == "--expected-sha256":
                        counts[0] += 1
                        node.elts[index + 1] = ast.Constant("0" * 64)
            return self.generic_visit(node)

        def visit_Call(self, node):
            if kind in ("checker-call", "timeout") and ast.unparse(node.func) == "subprocess.run":
                counts[0] += 1
                if kind == "timeout":
                    keyword = next(item for item in node.keywords if item.arg == "timeout")
                    keyword.value = ast.Constant(0)
                    return node
                return ast.parse(
                    "subprocess.CompletedProcess([], 0, stdout=json.dumps({"
                    "'status': 'PASS', 'scope': 'development-static-ELF-only', "
                    "'sha256': pin['sha256'], 'bytes': pin['size'], 'machine': 'x86_64'}), stderr='')",
                    mode="eval").body
            if kind == "artifact-call" and ast.unparse(node.func) == "read_artifact":
                counts[0] += 1
                return ast.parse("Path(artifact_path).read_bytes()", mode="eval").body
            return self.generic_visit(node)

        def visit_Expr(self, node):
            if (kind == "staged-call" and isinstance(node.value, ast.Call)
                    and ast.unparse(node.value.func) == "verify_staged_bundle"):
                counts[0] += 1
                return ast.Pass()
            return self.generic_visit(node)

        def visit_IfExp(self, node):
            if kind == "captured-copy" and isinstance(node.body, ast.Name) and node.body.id == "artifact":
                counts[0] += 1
                node.body = ast.parse("Path(artifact_path).read_bytes()", mode="eval").body
            return self.generic_visit(node)

    Mutator().visit(selected[0])
    if counts != [1] * len(counts):
        raise ValueError(f"mutation anchor count must be exactly one per guard: {counts!r}")
    changed = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(changed, str(BUILDER), "exec")
    return changed


def test_result(root, test):
    code = (
        "import io,json,sys,unittest\n"
        "sys.path.insert(0,sys.argv[1])\n"
        "suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[2])\n"
        "stream=io.StringIO(); result=unittest.TextTestRunner(stream=stream,verbosity=0).run(suite)\n"
        "print(json.dumps({'run':result.testsRun,'failures':[text for _,text in result.failures],"
        "'errors':[text for _,text in result.errors],'skips':[reason for _,reason in result.skipped],"
        "'unexpected_successes':len(result.unexpectedSuccesses)}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(root / "tests/podman/rootfs"), test],
        text=True, capture_output=True, timeout=60, check=False, cwd=root,
    )
    if result.returncode or result.stderr:
        raise ValueError("test process failed instead of returning a unittest result: " + result.stderr[-2000:])
    return json.loads(result.stdout)


def controls_pass(result):
    return (result["run"] == 1 and not result["failures"] and not result["errors"]
            and not result["skips"] and result["unexpected_successes"] == 0)


def assertion_detection(result):
    return (result["run"] == 1 and bool(result["failures"]) and not result["errors"]
            and not result["skips"] and result["unexpected_successes"] == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("new evidence file required; refusing overwrite")
    native = sys.platform.startswith("linux") and os.geteuid() == 0
    source = (ROOT / BUILDER).read_text()
    results, blocked = [], []
    with tempfile.TemporaryDirectory(prefix="sl-w1-mutations-") as temporary:
        repository = Path(temporary) / "repository"
        isolated_copy(repository)
        for gate in GATES:
            name, test, _, _, _, requires_linux = gate
            if requires_linux and not native:
                blocked.append({"gate": name, "test": test, "reason": "requires genuine Linux uid 0 fd fixtures"})
                continue
            entry = {"gate": name, "test": test}
            try:
                (repository / BUILDER).write_text(source)
                entry["control"] = test_result(repository, test)
                if not controls_pass(entry["control"]):
                    raise ValueError("unmodified control did not pass without errors/skips")
                changed = mutation(source, gate)
                (repository / BUILDER).write_text(changed)
                entry["mutated_source_sha256"] = hashlib.sha256(changed.encode()).hexdigest()
                entry["mutated"] = test_result(repository, test)
                entry["status"] = "DETECTED" if assertion_detection(entry["mutated"]) else "NOT_DETECTED"
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                entry.update(status="ERROR", error=str(error))
            results.append(entry)
    failed = any(item["status"] != "DETECTED" for item in results)
    report = {
        "schema": 1, "scope": "offline-W1-source-copy-guard-mutations",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "status": "FAIL" if failed else "BLOCKED" if blocked else "PASS",
        "detected": sum(item["status"] == "DETECTED" for item in results),
        "executed": len(results), "blocked": blocked, "results": results,
        "installed_runtime": "UNPROVEN; no execution or deployment",
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "detected", "executed")}, sort_keys=True))
    return 1 if failed or blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
