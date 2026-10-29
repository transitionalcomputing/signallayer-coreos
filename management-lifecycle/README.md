# P3-1b identity provisioning source

`identity.py` implements the source-only read/validate/plan/apply library in
issue #41. It is not an installed helper, executable, service, Cargo component
or credential API. No production invocation is authorized at this gate.
Python 3 is already present in the pinned Fedora base (see the maintained
pinned-base NEVRA measurement); the library uses only its standard library.
Later integration with the fixed native lifecycle still needs separate review
and authorization; this pass does not add an interpreted privileged helper.

The public mutation entry point `provision()` has no parameters and requires
host root. Fixed constants select the account databases, recovery record, lock,
home and shell. `_Store` and `_provision` are private fixture/integration
implementation details, not external interfaces. There is no CLI or test-root
flag. The fixture tests never call the live entry point as root.

The allocator chooses a free machine-local system UID/GID in 100–999 and the
lowest free 65,536-aligned extent at or above 100000, excluding primary IDs and
both mapping spaces. Existing unrelated entries are preserved byte-for-byte.
An unrecorded pre-existing management account is ambiguous and refused; it is
not seized merely because its attributes look right. `sl-runtime` is untouched.
All existing mapping owners must resolve in local passwd; multiple extents for
one owner, duplicate numeric account IDs and inconsistent shadow databases are
conservatively refused. The live entry accepts only an explicit files-first local/systemd NSS policy
and corroborates candidate IDs, names, ranges and memberships through NSS.
Remote/directory providers, missing or unsupported policy fail closed without
changing configuration. NSS tests are simulated; actual target-host NSS and
dynamic-ID behavior remain an integration gate.

Under fixed recovery and standard password-database locks, fsynced prepared
metadata records only the intended identity and before/after file hashes (no
credential copies). Each database is atomically replaced separately. Retry
accepts only the recorded before/after states, reconstructs the missing writes,
and validates the final snapshot before publishing committed metadata. Drift
or ambiguity refuses without destructive rollback. Any existing application
or runtime state forbids initial allocation or completion of partial mappings.
Consumers must refuse to launch Podman until committed identity validation
succeeds; a partly updated set of account files alone is not authorization.
Accepted values survive code/build changes; they are not deployment-selected.

FD-relative no-follow traversal checks trusted ownership, permissions, types
and hardlinks. Existing xattrs, including SELinux labels, are preserved during
replacement; capability-bearing account files are rejected. File security is
checked by permitted access, not exact checkout-style mode equality. Account
files, metadata and locks may not be group/other writable; private records may
not be group/other readable. Source-only tests do not establish loaded-policy
permission to relabel replacement inodes or correct initial labels for absent
subid/metadata files. Fedora installation, SELinux, cross-process account-tool
cooperation, actual reboot/update/rollback and Podman behavior remain UNPROVEN.

Run disposable tests with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/podman/identity -v
```

No numeric ID, map or runtime directory is embedded into the immutable image;
the returned identity is the only source for later UID-dependent resolution.
