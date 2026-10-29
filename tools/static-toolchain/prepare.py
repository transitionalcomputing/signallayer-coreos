#!/usr/bin/python3
"""Prepare only a disposable rootless OCI builder from an offline RPM lock.

Not a host installer. No repository/network resolution, production image stage,
or acceptance of discovered dependency versions is provided by this helper.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


BASE_REFERENCE = (
    "ghcr.io/transitionalcomputing/signallayer-base@sha256:"
    "ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c"
)
BUILD = Path("/build")
RPM_QUERY = "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"
HEX = re.compile(r"[0-9a-f]{64}\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.~\-]*\.rpm\Z")
EXPECTED_FLAGS = ['--edition=2021', '--target=x86_64-unknown-linux-gnu', '-Ctarget-feature=+crt-static', '-Crelocation-model=static', '-Copt-level=2', '-Cpanic=abort', '-Ccodegen-units=1', '-Cdebuginfo=0', '-Clink-arg=-Wl,--build-id=none', '--remap-path-prefix=/tmp/sl-f5-compile=/usr/src/signallayer-fixture']
COMMANDS = {
    "rust": ["rustc", "--version"],
    "cargo": ["cargo", "--version"],
    "gcc": ["gcc", "-dumpfullversion"],
    "binutils": ["ld", "--version"],
}


class PreparationError(Exception):
    """An input or measurement differs from the reviewed build-only lock."""


def run(argv: list[str], *, timeout: int = 120) -> str:
    result = subprocess.run(
        argv,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode:
        raise PreparationError(f"command failed ({result.returncode}): {argv!r}\n{result.stdout}")
    return result.stdout


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise PreparationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def require_rootless_build_namespace() -> None:
    if os.geteuid() != 0 or Path(__file__).resolve() != BUILD / "prepare.py":
        raise PreparationError("run only as namespaced root at /build/prepare.py in the isolated OCI build")
    for name in ("uid_map", "gid_map"):
        rows = Path("/proc/self", name).read_text(encoding="ascii").splitlines()
        mappings = [tuple(map(int, row.split())) for row in rows]
        if not mappings or any(len(row) != 3 for row in mappings):
            raise PreparationError(f"invalid {name}")
        if not any(inside == 0 and outside != 0 and length > 0 for inside, outside, length in mappings):
            raise PreparationError(f"{name} does not map root to an unprivileged host identity")
        if any(outside == 0 for _, outside, _ in mappings):
            raise PreparationError(f"{name} maps host root; refusing host/rootful installation")


def regular_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise PreparationError(f"not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise PreparationError(f"input changed during read: {path}")
        return data
    finally:
        os.close(fd)


def installed_nevras() -> list[str]:
    values = run(["rpm", "-qa", "--qf", RPM_QUERY]).splitlines()
    if not values or any(not value for value in values) or len(set(values)) != len(values):
        raise PreparationError("empty or duplicate installed RPM inventory")
    return sorted(values)


def inventory_digest(values: list[str]) -> str:
    return hashlib.sha256(("\n".join(values) + "\n").encode("ascii")).hexdigest()


def validate_lock(lock: dict) -> None:
    if not isinstance(lock, dict):
        raise PreparationError("toolchain lock must be a JSON object")
    if lock.get("schema_version") != 1 or lock.get("scope") != "development-only-static-toolchain":
        raise PreparationError("unsupported toolchain lock schema/scope")
    base = lock.get("base", {})
    if base.get("reference") != BASE_REFERENCE:
        raise PreparationError("base reference differs from the approved immutable base")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", base.get("pinnedimage_id", "")):
        raise PreparationError("missing immutable base image ID")
    if not HEX.fullmatch(base.get("installed_nevras_sha256", "")):
        raise PreparationError("missing pinned base inventory digest")
    values = lock.get("installed_nevras")
    if not isinstance(values, list) or not values or values != sorted(set(values)):
        raise PreparationError("expected final NEVRAs must be a nonempty sorted unique list")
    if any(not isinstance(value, str) or not value.isascii() or "\n" in value for value in values):
        raise PreparationError("invalid final NEVRA")
    if lock.get("target") != "x86_64-unknown-linux-gnu":
        raise PreparationError("unsupported fixture target")
    if lock.get("signing_key_fingerprint") != "36f612dcf27f7d1a48a835e4dbfcf71c6d9f90a6":
        raise PreparationError("Fedora44 signing key identity mismatch")
    versions = lock.get("versions", {})
    if set(versions) != set(COMMANDS) or any(not isinstance(v, str) or not v for v in versions.values()):
        raise PreparationError("all four compiler/tool version strings are required")
    if any(not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", v) for v in versions.values()):
        raise PreparationError("compiler/tool versions must be numeric release versions")
    source = lock.get("source", {})
    if source.get("path") != "management-fixture/src/main.rs" or not HEX.fullmatch(source.get("sha256", "")):
        raise PreparationError("missing fixed fixture source identity")
    if lock.get("compiler_flags") != EXPECTED_FLAGS:
        raise PreparationError("compiler flags differ from the fixed static fixture recipe")
    repositories = lock.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise PreparationError("missing repository provenance")
    repo_ids = set()
    for repo in repositories:
        if not isinstance(repo.get("id"), str) or repo["id"] in repo_ids:
            raise PreparationError("missing or duplicate repository identity")
        if not isinstance(repo.get("url"), str) or not repo["url"].startswith("https://"):
            raise PreparationError("repository provenance requires HTTPS")
        if not HEX.fullmatch(repo.get("repomd_sha256", "")):
            raise PreparationError("missing repository metadata digest")
        repo_ids.add(repo["id"])
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise PreparationError("missing offline RPM closure")
    filenames, names = set(), set()
    for package in packages:
        filename, name = package.get("filename", ""), package.get("name")
        if not FILENAME.fullmatch(filename) or filename in filenames:
            raise PreparationError("invalid or duplicate RPM filename")
        if not isinstance(name, str) or not name or name in names:
            raise PreparationError("missing or duplicate RPM package name")
        if not isinstance(package.get("nevra"), str) or package["nevra"] not in values:
            raise PreparationError("RPM absent from expected installed closure")
        if not HEX.fullmatch(package.get("sha256", "")):
            raise PreparationError("missing RPM digest")
        if type(package.get("size")) is not int or package["size"] <= 0:
            raise PreparationError("invalid RPM size")
        if package.get("repo_id") not in repo_ids:
            raise PreparationError("RPM repository not represented in pinned metadata")
        if not isinstance(package.get("url"), str) or not package["url"].startswith("https://"):
            raise PreparationError("RPM provenance requires HTTPS")
        filenames.add(filename)
        names.add(name)

    by_name = {p['name']: p for p in packages}
    required = {'rust', 'cargo', 'gcc', 'binutils', 'glibc', 'glibc-devel', 'glibc-static', 'rust-std-static'}
    if not required <= names:
        raise PreparationError('missing compiler/static library packages')
    for package in packages:
        pattern = re.escape(package['name']) + r'-[0-9]+:[A-Za-z0-9+_.~]+-[A-Za-z0-9+_.~]+\.(?:x86_64|noarch)'
        if re.fullmatch(pattern, package['nevra']) is None:
            raise PreparationError('floating or malformed exact NEVRA')
    glibc = by_name['glibc']['nevra'].removeprefix('glibc-')
    for name in ('glibc-devel', 'glibc-static'):
        if by_name[name]['nevra'].removeprefix(name + '-') != glibc:
            raise PreparationError('glibc/static/devel version mismatch')
    for package, version_key in [('rust','rust'),('cargo','cargo'),('gcc','gcc'),('binutils','binutils')]:
        if not by_name[package]['nevra'].startswith(package + '-0:' + versions[version_key] + '-'):
            raise PreparationError('toolchain package/version mismatch')


def verify_rpms(lock: dict) -> tuple[list[str], dict[str, str]]:
    directory = BUILD / "rpms"
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise PreparationError("RPM cache must be a real directory")
    expected = {package["filename"] for package in lock["packages"]}
    if {entry.name for entry in directory.iterdir()} != expected:
        raise PreparationError("RPM cache must contain exactly the locked filenames")
    paths, signatures = [], {}
    for package in sorted(lock["packages"], key=lambda item: item["filename"]):
        path = directory / package["filename"]
        data = regular_bytes(path)
        if len(data) != package["size"] or hashlib.sha256(data).hexdigest() != package["sha256"]:
            raise PreparationError(f"RPM size/digest mismatch: {path.name}")
        queried = run(["rpm", "-qp", "--qf", "%{NAME}\\n" + RPM_QUERY, str(path)]).splitlines()
        if queried != [package["name"], package["nevra"]]:
            raise PreparationError(f"RPM metadata mismatch: {path.name}")
        signature = run(["rpmkeys", "--checksig", str(path)])
        if not re.search(r"\bsignatures\s+OK\b", signature) or re.search(r"NOKEY|NOT OK|NOTOK|BAD", signature):
            raise PreparationError(f"RPM signature not verified with existing trusted keys: {path.name}")
        verbose = run(["rpmkeys", "--checksig", "-v", str(path)])
        if lock["signing_key_fingerprint"] not in verbose or "signature" not in verbose.lower() or re.search(r"NOKEY|NOT OK|NOTOK|BAD", verbose):
            raise PreparationError("RPM signing key differs from the pinned Fedora44 key")
        signatures[path.name] = verbose
        paths.append(str(path))
    return paths, signatures


def main() -> None:
    require_rootless_build_namespace()
    lock_bytes = regular_bytes(BUILD / "lock.json")
    lock = json.loads(lock_bytes, object_pairs_hook=reject_duplicate_keys)
    validate_lock(lock)
    before = installed_nevras()
    if inventory_digest(before) != lock["base"]["installed_nevras_sha256"]:
        raise PreparationError("actual base RPM inventory differs from the pinned base")
    paths, signatures = verify_rpms(lock)
    command = ["dnf", "-y", "--disablerepo=*", "--setopt=install_weak_deps=False", "install", *paths]
    install_output = run(command, timeout=600)
    after = installed_nevras()
    if after != lock["installed_nevras"]:
        raise PreparationError("installed toolchain closure differs from the reviewed exact NEVRA set")
    tool_output = {name: run(argv).splitlines()[0] for name, argv in COMMANDS.items()}
    for name in ("rust", "cargo"):
        executable = "rustc" if name == "rust" else "cargo"
        if not tool_output[name].startswith(executable + " " + lock["versions"][name] + " "):
            raise PreparationError(f"actual {name} version differs from the lock")
    if tool_output["gcc"] != lock["versions"]["gcc"]:
        raise PreparationError("actual gcc version differs from the lock")
    if "GNU ld" not in tool_output["binutils"] or not re.search(
        r"(?<![0-9.])" + re.escape(lock["versions"]["binutils"]) + r"(?![0-9.])",
        tool_output["binutils"],
    ):
        raise PreparationError("actual GNU ld version differs from the lock")
    evidence = {
        "schema_version": 1,
        "scope": lock["scope"],
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "base_nevras": before,
        "installed_nevras": after,
        "installed_nevras_sha256": inventory_digest(after),
        "versions": lock["versions"],
        "tool_output": tool_output,
        "gcc_verbose": run(["gcc", "--version"]),
        "rustc_verbose": run(["rustc", "-vV"]),
        "rpm_signatures": signatures,
        "installation_command": command,
        "installation_output": install_output,
        "production_coreos_changed": False,
    }
    target = BUILD / "preparation-evidence.json"
    if target.exists() or target.is_symlink():
        raise PreparationError("refusing to replace preparation evidence")
    fd, temporary = tempfile.mkstemp(prefix=".preparation-", dir=BUILD)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("PASS: isolated offline static-build toolchain matches its lock")


if __name__ == "__main__":
    try:
        main()
    except (PreparationError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(f"FAIL: {error}") from error
