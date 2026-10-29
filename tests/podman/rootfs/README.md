# P3-1c offline Candidate C rootfs fixtures

Issue #43 authorizes these source-only tests. They do not install a rootfs,
package an executable, start a service, build an image or prove runtime trust.
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
python3 tools/build-management-rootfs --offline-output /tmp/rootfs-fixture/bundle
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
this tool does not authorize or certify any runtime mount. No runnable
entrypoint is packaged while the static-toolchain mismatch remains blocked.

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
