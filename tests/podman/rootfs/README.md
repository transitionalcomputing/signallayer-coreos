# P3-1c offline Candidate C rootfs fixtures

Issue #43 establishes the source-only oracle; the owner-approved W1 seam adds
offline packaging of exactly the reviewed F5 executable. These tests do not
install a rootfs, execute the fixture, start a service, build an image or prove
runtime trust.
Run in the **already cached pinned Fedora base**, as uid 0 inside a disposable
rootless container with networking disabled. Do not run against installed `/usr`.
A host invocation without Linux uid 0 skips the materialization tests and is
**not** the reported native result.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/podman/rootfs -v
```

No installs/downloads are required. Python's standard library and Linux fd/xattr
APIs suffice. Source is supplied by a tar stream into the container's temporary
filesystem; there is no host-root bind, privileged mode or SELinux bypass.

The fixed source selection is `management-fixture/rootfs-spec.json` and its
explicit SHA-256-pinned inputs. `tools/build-management-rootfs` compiles the
expected manifest **before** creating the tree. The independent
`tools/verify-management-rootfs` imports no builder/scanner implementation.

Inside the disposable environment, a CLI roundtrip is:

```sh
mkdir -m 0700 /tmp/rootfs-fixture
python3 tools/build-management-rootfs \
  --fixture-artifact /tmp/reviewed-native/sl-management-fixture \
  --offline-output /tmp/rootfs-fixture/bundle
python3 tools/verify-management-rootfs \
  --offline-bundle /tmp/rootfs-fixture/bundle \
  --expected-manifest-sha256 <hash-from-the-trusted-build-record>
```

The expected hash must be pinned from the controlled source/build record,
separately from the tree being checked. Hashing an attacker-supplied manifest
and supplying that same hash is **not** an independent oracle or provenance
verification. These are explicit offline tooling arguments, not a runtime
caller-selected rootfs/manifest/entrypoint interface. No installed invocation
exists; omitting arguments fails.

The bundle contains exactly `rootfs/` and canonical `manifest.json`. Its
manifest describes normalized paths, root ownership, modes, content digests,
symlink targets, hardlink equivalence and exact empty non-SELinux xattrs.
Build identity is the SHA-256 of canonical source/entries/exclusions data.
Timestamps in the rootfs are normalized; the manifest does not use temporary
paths, input mtimes, checkout rw bits or machine-local management UID/GID.

`selinux: UNPROVEN` deliberately refuses an installed label claim: the adopted
contract has not named the production rootfs type. No relabeling/policy is
performed. A test rejecting a claimed context is a parser negative, **not**
proof of actual SELinux label-drift detection. Exact expected context and
loaded-policy comparison belong to the separately reviewed policy gate.

There are **no measurement exclusions** in the offline tree (`dynamic_mounts`
must be empty). `/run`, `/tmp`, `/var` and the empty application-data placeholder
are mount targets, not permission to ignore their offline contents. `/etc/mtab`
→ `/proc/mounts` is the sole external symlink exception inherited from Candidate
C feasibility; `/run/.containerenv` is present. Later exact tmpfs/application-
data mounts must remain outside code, libraries, loaders and bootstrap config;
this tool does not authorize or certify any runtime mount. W1 packages only
the F5-pinned `usr/bin/sl-management-fixture`, root:root, mode 0555. It does
not prove execution in this minimal rootfs or authorize a runtime entrypoint.

Real fixture mutations cover bytes, names, directories, ownership, modes,
link groups, xattrs, FIFOs and sockets. Mount-ID changes, capability reporting
and in-flight races include injected observations; device types are rejected
at the recipe boundary. These do not prove privileged mount attacks, actual
capability installation or running-content/PID namespace measurement. The
interruption fixture raises before publication, not a power-loss test.

Bundle publication uses a private staging directory under a root-owned parent
that must not be group/world writable. Existing outputs are refused. One
trusted builder owns that parent; concurrent hostile root writers are outside
this model. Atomic rename is not a general no-replace or crash-durability
protocol. The independent verifier rejects an incomplete/mismatched bundle.

## R1 prepublication gate and R2 source identity

The builder now invokes the fixed sibling `verify-management-rootfs` as an
external isolated Python process **on staging before rename**. The digest is
compiled from the reviewed recipe before any tree is created. A missing,
timed-out, nonzero, malformed or unexpected verifier result refuses publication;
only the exact matching offline PASS result permits rename and builder PASS.
The verifier remains a separate implementation; its functions are not imported
into the builder.

The Linux suite requires the already installed `setfacl`/`getfacl`. It creates a
root-owned `0700` disposable output parent with `setfacl -d -m u:nobody:rwx`, checks
that the default ACL is real, and asserts CLI refusal with no PASS, target or
leftover staging. Lack of ACL tooling/filesystem support fails this gate rather
than silently simulating or skipping it. Clean-parent publication and injected
verifier failures are separate controls.

`expected-source-identity.json` pins the independently reviewed canonical
manifest hash and build ID. A test derives these from source without creating a
tree and compares exact values. Updating the fixture is an explicit reviewed
content-identity change, not an automatic regeneration step or a signature.

## R3 installed-path gate and R4 checkout paths

Offline fixture ancestors may include `/tmp`; this does not certify a trusted
installed ancestry. Before any installed integration, require fd-anchored proof
of the exact booted-deployment rootfs/manifest paths, root ownership and absence
of runtime-UID-writable/group/world-writable ancestors, no symlink/mount escape,
read-only deployment origin and the approved loaded SELinux labels. Those
installed checks remain UNPROVEN; no production verifier mode is added here.

The source builder intentionally refuses checkout paths traversing symlinks,
including image-mode hosts' `/home -> /var/home`. Invoke it through the physical
checkout path (for example `/var/home/...`), not a symlink spelling. There is no
implicit `resolve()` fallback. A JSON lone-surrogate recipe path now fails with
controlled `BuildError` instead of an encoding traceback.


## W1 fixed executable input

The CLI requires `--fixture-artifact`; it accepts no source/hash/destination,
mode, argv or toolchain override. The fixed F5 lock and its unchanged source
contract bind the artifact size/digest, target, fixture source and independent
ELF checker. Both lock/contract hashes become source inputs in the manifest.
The expected manifest is compiled before reading supplied bytes or creating a
rootfs. Missing input is an error; the builder never downloads or recompiles.

The input is read once through no-follow fd traversal, bounded by the reviewed
size. Aliases, special objects/bits, unreviewed xattrs (including ACL/capability),
writable ownership/modes and observed mount/inode/content substitution fail.
Ancestors are revalidated; the offline input is not an installed-path authority.
The captured bytes must match the reviewed hash and size. The captured,
source-hash-checked independent ELF checker inspects a private copy with the
reviewed expected hash. Only those same captured bytes reach materialization;
there is no later unverified read of the supplied pathname. This never executes
the supplied ELF. Rootfs staging still requires the separate original verifier
before publication.

Tests use an explicitly synthetic 512-byte structural ELF and a **private copy**
of the source lock/contract. They cannot authorize production output. Production
F5 pins stay unchanged. Portable controls exercise source/pin and verification
logic with the fd-capture boundary mocked; Linux uid0 tests cover actual fd,
metadata and materialization behavior. Neither proves installed SELinux or NSS
compatibility. The reviewed 15,725,600-byte native ELF is required separately
for a real offline roundtrip; absence blocks that evidence gate, never triggers
a synthesized/rebuilt replacement.

`0.0.4-w1-manifest-comparison.json` records the explicit old-to-new source
identity diff: one executable entry and the F5 lock/contract provenance, with
all previous tree entries unchanged. Historical data-only evidence is preserved.
The golden is review evidence, not a self-approval mechanism. Run focused strict
mutation controls using `tests/podman/rootfs/mutation_w1.py`; skips, errors or an
invalid mutation do not count as a detected bypass. See the W1 findings for the
actual command results and any blocked native gates.
