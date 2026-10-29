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
conservatively refused.

The live entry requires explicit files-first `passwd`, `group` and `shadow`
policies using only the local `files` and `systemd` providers. The only accepted
action token is `[SUCCESS=merge]` between accepted `group` providers; it does
not authorize another provider. An explicit `gshadow` policy uses the same
`files`/`systemd` restriction as `shadow`. `subid` must be absent or exactly
`files`; absent-entry acceptance follows the documented shadow-utils 4.19
local-files fallback. `initgroups` must be absent or use only the providers
accepted by `group`. Candidate IDs, names and ranges are corroborated through
NSS. For an existing local management account, effective supplementary
membership must be checked through `getgrouplist`; `getgrall().gr_mem` alone
is insufficient. First creation requires a pre-allocation membership check
and a post-creation recheck before the durable record is committed.
Missing, unreadable, duplicate or unsupported identity policy fails closed
without changing configuration. NSS policy fixtures are simulated; actual
installed NSS and dynamic-ID behavior remain integration gates.

The no-follow policy for `etc/nsswitch.conf` is unchanged. An authselect-managed
symlink is therefore refused with a structured diagnostic, even if its target
would contain otherwise supported local policy. That compatibility limit is
explicit; this pass does not follow the link or add a path allowlist.

`altfiles` is explicitly unsupported. Before accepting an image-mode NSS
configuration that uses it, separately authorized integration must account for
`/usr/lib/passwd` and `/usr/lib/group` in the occupied-ID/name snapshot and
refuse collisions introduced by update or rollback before any runtime launch.
Do not relax this refusal to make startup succeed. Read-only measurement of
the exact pinned base confirmed both `altfiles` in its effective policy and an
authselect-managed `etc/nsswitch.conf` symlink. This source therefore remains
incompatible with that actual base configuration by design; accepting the
local-policy fixture is not proof that stock-target provisioning succeeds.
See [the recorded NSS measurement](../docs/evidence/0.0.4-p3-1b-nss-review.json).

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

## Review limits and recovery handoff

The following limitations are recorded from independent review, not corrected
or accepted as production behavior at this source-only gate:

- Recovery diagnostics do not consistently identify the fixed path and its
  before/after/neither classification. Traversal failures can appear as a
  general lock failure. A permanent prepared-record refusal requires a
  separately reviewed recovery procedure; there is no automatic rollback or
  authorized manual record deletion.
- A crash after writing a replacement temporary file but before rename can
  leave a root-owned `.sl-identity-*` file containing private account-file
  content. Preserved ownership, mode and label keep it private, but it is not
  yet removed on retry and can survive an `/etc` deployment merge. Existing
  durable-boundary tests interrupt after completed replacements; this
  pre-rename crash window is not covered or claimed tested.
- Valid configurations are conservatively refused: multiple subordinate
  extents for one owner, Podman's `containers:2147483647:2147483648` auto-owner
  line, directory-service group members or mapping owners, duplicate UIDs,
  and account names beginning with a digit. These are compatibility limits,
  not demonstrated security bypasses.
- The source allocator still uses UID/GID floor 100. Fedora's `SYS_UID_MIN=201`
  reserves lower static IDs; this discrepancy is an explicit integration
  limitation, not approval to allocate those IDs in production.
- A sysusers declaration that creates `sl-management` first would be refused
  as an ambiguous pre-existing account. Tmpfiles must not create either
  management application or runtime state before provisioning: existence
  itself blocks initial allocation. Missing ancestors currently become mode
  `0700`, unlike P3-0's proposed traversable `0711` parent. Ordering and parent
  permissions require separately authorized installed integration.
- The planned lifecycle is native Rust. Installing this Python source as a
  privileged helper is not authorized by the source gate; integration needs
  an approved port or an explicitly approved interpreted path using isolated
  `python3 -I`. No installed integration is proved by this library.

On a refusal, preserve the databases and private recovery record for
investigation. Do not remove the record, alter mappings or launch Podman to
force progress. The next authorized recovery work must distinguish transaction
state and unrelated account changes before proposing a repair.
