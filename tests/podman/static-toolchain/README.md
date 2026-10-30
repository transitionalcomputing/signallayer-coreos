# Development-only static fixture toolchain

Issue #45 separates the Candidate C static fixture compiler from the approved
CoreOS runtime base. This source gate prepares a disposable rootless builder,
compiles only `management-fixture/src/main.rs`, independently inspects its ELF
output, and runs a bounded compatibility smoke test. It does not install the
fixture, produce a production rootfs, or authorize P3-1d integration.

## Fixed inputs and offline execution

`config/static-fixture-toolchain.json` records the immutable base reference and
image ID, base inventory digest, repository metadata digests, exact RPM
transaction bodies and their hashes, expected complete builder inventory,
compiler versions, fixed source digest, fixed compiler flags, and the reviewed
artifact SHA-256 and size. Every compilation must match that preexisting
artifact identity before the independent ELF check, which receives the reviewed
digest. Agreement between two newly measured hashes alone is insufficient.
These are expected inputs, not evidence that a build has passed.

Repository metadata hashes are recorded provenance, not enforced repository
snapshot integrity: the offline build neither fetches nor revalidates metadata.
It enforces the exact RPM byte hashes, NEVRAs and Fedora signatures instead.

`tools/static-toolchain/Containerfile` is a separate development-only recipe.
Its preparation helper refuses direct host installation, checks the rootless
namespace, verifies cached RPM identities and signatures against the pinned
Fedora signing key, disables all repositories, and installs only the local
locked transaction. The resulting inventory and compiler versions must match
the lock; discovery never updates that expectation. The production
`Containerfile`, pinned base and CoreOS package inventory are not changed.

Prerequisites are rootless Podman on native Linux x86_64, the already cached
exact base image, and a real directory containing **exactly** the RPM filenames
in the lock. An incomplete, extra, symlinked or modified cache is refused. The
entry point does not download packages, resolve a floating repository, install
host packages, or accept arbitrary source/compiler arguments.

From the repository root, with a reviewed cache and an existing output parent:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tests/podman/static-toolchain -v

python3 tools/build-static-fixture \
  --rpm-cache /path/to/exact-locked-rpm-cache \
  --output /path/to/existing-parent/new-static-fixture-run
```

The output directory must not already exist. A failed invocation retains
diagnostic output and must not be described as accepted merely because it
produced an intermediate binary or builder image. The build uses
`--isolation=oci --pull=never --network=none --no-cache` for fresh preparation,
records preparation provenance, performs two compilations in separate disposable
containers from **one** prepared builder image, checks both against the reviewed
digest/size, compares their hashes, checks
the fixed output set, and runs missing-compiler/static-library controls in
disposable writable container layers. It never deletes those files from the
image or host. Container cleanup is scoped to each owned name. The prepared
builder image is intentionally retained for provenance inspection and review;
image pruning is not part of this tool. Builder-image byte reproducibility is
not claimed.

Inspect `preparation-evidence.json`, both `compile-*/static-check.json` records,
the header/program/dynamic/symbol listings, negative controls and `result.json`.
Only a completed `result.json` with `status=PASS` reports this bounded workflow
as passing. Preserve the lock hash, exact source commit, raw logs and binary
hash alongside it. The [corrected complete native result](../../../docs/evidence/0.0.4-f5-c1c2-native-result.json)
records one fresh end-to-end execution of the corrected revision; the
[remediation index](../../../docs/evidence/0.0.4-f5-c1c2-tests.json) binds its
transcripts and the 27-mutation proof. Earlier split evidence is retained as
history, not proof of the corrected full pipeline. Offline tests alone do not
establish a successful compilation. A negative control requires ordered in-container
readiness/removal/cause/result witnesses and its exact reserved failure exit;
an arbitrary Podman or infrastructure error must fail evaluation.

The independent checker can also inspect an artifact against a separately
recorded digest without executing it:

```sh
python3 tools/verify-static-fixture \
  --artifact /path/to/sl-management-fixture \
  --expected-sha256 RECORDED_LOWERCASE_SHA256
```

The C2 mutation replay removes execution guards only in isolated source copies;
syntax/import errors do not count as detection. Run it after the focused suite:

```sh
python3 tests/podman/static-toolchain/run-mutations.py --output /path/to/new-mutations.json
```

## Evidence limits and hostile controls

The offline suite uses synthetic ELF files and mocked package-command results
to exercise malformed/truncated objects, wrong architecture/ABI, interpreter
and dependency tags, executable-stack/writable-executable segments, digest and
input drift, cache substitutions, missing compiler/static-library inputs,
signature failures and namespace refusal. Its results describe checker behavior,
not installed SELinux enforcement, rootless management confinement or KVM.

The ELF checker requires bounded little-endian x86_64 ELF, an executable
file-backed entrypoint, a non-executable GNU stack, no writable executable load
segment, no `PT_INTERP`, and no declared dynamic library/search/audit dependency.
Static PIE may legitimately have `ET_DYN` and `PT_DYNAMIC`; the checker requires
its PIE declaration rather than rejecting dynamic tables indiscriminately.

These checks establish ELF linkage properties, not generic self-containedness.
glibc NSS can use separate modules, and explicit `dlopen`, locale/configuration
reads or future fixture code are not excluded by absence of `DT_NEEDED`.
Preserved unstripped symbol listings help inspection; a loader symbol's presence
does not prove the fixed success path calls it. The source currently prints one
constant and makes no explicit NSS or plugin call. Do not extrapolate this
fixture result to arbitrary Rust/glibc applications.

The runtime smoke executes the fixed binary as numeric UID/GID 65532 in the
**original approved base**, with a read-only container root, no network and no
capabilities; its temporary binary is transferred through stdin. This checks the
fixture's exact stdout, exit status and compatibility with that base. The base
still contains libraries and configuration, so this is not empty-root execution
or proof that NSS/dlopen dependencies could never arise. No live management
identity is provisioned or used.

Production binary/rootfs packaging, installed ancestry and label validation,
dedicated SELinux transitions, management runtime isolation, lifecycle recovery
and A-to-B-to-A acceptance remain separate authorized gates. This tooling does
not modify release identity or publish a release.

## Primary references

- [Rust Reference: static and dynamic C runtimes](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes)
  documents `crt-static` and recommends inspection of the resulting binary.
- [ELF gABI: program loading](https://gabi.xinuos.com/elf/07-pheader.html) defines
  program headers, `PT_INTERP` and segment permissions.
- [ELF gABI: dynamic linking](https://gabi.xinuos.com/elf/08-dynamic.html) defines
  the interpreter, dynamic table and `DT_NEEDED` dependencies.
- [GNU libc: NSS basics](https://sourceware.org/glibc/manual/latest/html_node/NSS-Basics.html)
  and [adding an NSS service](https://sourceware.org/glibc/manual/latest/html_node/Adding-another-Service-to-NSS.html)
  describe external database-service modules.
