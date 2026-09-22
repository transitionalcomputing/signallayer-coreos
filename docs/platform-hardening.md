# Phase 3B platform service boundary

The platform boundary remains the system-bus service
`org.signallayer.Platform1` at `/org/signallayer/Platform1`. Status schema
`0.2` adds independent update and rollback lifecycle state. `corectl` remains
an IPC client; administrative mutation methods are root-only and may control
only their exact image-owned systemd units.

## Image-owned SELinux integration

`image/platform/selinux/sl_platformd.te` and `.fc` define the daemon domain,
entry point, release metadata and private temporary types. The same pinned
Fedora base supplies the policy development interfaces in a separate build
stage. The final image receives the compiled package and installs it with
`semodule -n -i`: this updates the base's `/etc/selinux` policy store without
loading policy into the build host. The derived runtime omits Fedora's inherited
standalone `semodule_package`, `semodule_unpackage`, `semodule_link` and
`semodule_expand` build helpers after installation, retaining policycoreutils
runtime administration and its supported store backend. It also omits the
base's two authoring interfaces, `container.if` and `passt.if`; their compiled
runtime policy modules remain installed. Upstream categorizes
these as [policy build tools](https://github.com/SELinuxProject/selinux/wiki/Tools);
source compilers, policy development interfaces and setools also stay outside
the final image. The pinned Fedora base remains unchanged.
There is no first-boot policy installer,
manual labeling step, permissive type, unconfined attribute or unconfined
backend helper.

Bootc applies installed labels from the image's policy and file contexts;
container-layer `chcon` and OCI SELinux xattrs are not the installation
mechanism. See the upstream [image-labeling documentation](https://bootc.dev/bootc/bootc-images.html).
The expected entry point is `sl_platformd_exec_t`; release metadata is
`sl_platformd_release_t`. The policy includes an explicit PID 1 transition
and the corresponding `nnp_transition` permission, preserving
`NoNewPrivileges=yes`. A label alone does not demonstrate confinement: acceptance
requires the actual process context, loaded transition/rules/attributes,
non-permissive state, and an actual denied access with a matching AVC.

The daemon stays root with only `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE`, preserving
the Phase 3A sandbox. Bootc's supported status path prepares a private mount
namespace and locks deployment state. Removing the capability set fails its
root-privilege check; SYS_ADMIN alone cannot inspect PID 1's namespace.
Fedora's `init_read_state` interface grants read-only PID 1 directories,
files and namespace links; it does not grant process attachment/tracing.
The first clean candidate exposed missing directory traversal, suppressed by
the base daemon `dontaudit`, despite the explicit file-read rule.
Acceptance inspects this distinction in
the loaded policy, alongside the unchanged Linux capability bound.
The daemon invokes only `/usr/bin/bootc status --json`, never a shell or
caller-provided executable/arguments.

Bootc also invokes fixed `findmnt` and `lsblk` inspection helpers; acceptance
records their executable labels and checks permitted child transitions.
The pinned bootc SELinux preflight executes `chcon` against a private
temporary file using an intentionally invalid type. Without CAP_MAC_ADMIN this
probe fails, and bootc copies, relabels and re-executes its own binary.
The pinned status preparation path tolerates a failed repeated privilege probe;
it does not invoke the enforcement fallback used by installation operations.
Permissions for its private temporary type and execution
of `install_exec_t` must keep that child in `sl_platformd_t`; the Fedora
installer domain `install_t` is unconfined and is not an acceptable backend
transition. CAP_MAC_ADMIN and permission to disable enforcement/load policy
are not added. The invalid-label probe's inherited SELINUX_ERR warnings must
be distinguished from unexpected AVC denials in the confined domain.
Policy read permissions cover runtime libraries, installed release data,
SELinux file contexts, cgroup CPU quota reads for Rust runtime sizing, the
booted-host marker, diagnostic datagram sockets and the system bus/systemd
health exchange. The D-Bus XML associates only the
platform name with the daemon SID; policy permits acquiring that SID rather
than arbitrary names using the bus default SID. The root-only XML ownership
rule and exact unprivileged status allowance are preserved. See the upstream
[SELinux name association](https://dbus.freedesktop.org/doc/dbus-daemon.1.html)
documentation. Substantial
backend permissions must be justified against native guest observations in
that build's acceptance report.

Clean candidate 04 reached the checksum step but exposed a denied read of
`/etc/selinux/targeted/policy`, labeled `semanage_store_t`. Fedora's
`seutil_read_module_store` interface grants only module-store listings and
file/link reads, without store management or kernel policy loading.

Clean candidate 09 advanced past that step and exposed read-only status-path
denials for `cert_t:dir search` and `fs_t:filesystem getattr`. Fedora's
`miscfiles_search_generic_cert_dirs` interface permits directory traversal
without certificate-file reads. This distinction matters because Fedora also
labels generic TLS keys `cert_t`. `fs_getattr_xattr_fs` permits only persistent
filesystem metadata queries. Neither grants filesystem writes/mounts, policy
administration or additional Linux capabilities. Candidate 10's broader generic
certificate-read proposal was superseded before disk construction.

Clean candidate 11 exposed reads of public `openssl.cnf` (also `cert_t`), a
denied udev-database traversal, and missing block-device metadata access.
The image copies Fedora's public OpenSSL configuration and its packaged
provider fragment under `/usr/lib/signallayer`. Only the provider-directory
include is relocated; provider bytes and the original absolute crypto-policy
include are preserved. The fixed backend sets `OPENSSL_CONF` to this read-only
image copy, using OpenSSL's supported
[configuration path](https://docs.openssl.org/3.5/man5/config/#environment).
Original system configuration/labels remain intact, and the daemon receives no
generic certificate/key-file read permission. These are configuration snapshots
for this image's status backend; subsequent image builds refresh them from the
pinned base. Acceptance verifies source equivalence, provider set, modes and
the real held child's configuration environment.

Fedora's `udev_read_db` interface permits only database listings/file/link reads;
`storage_getattr_fixed_disk_dev` permits device metadata without raw block reads.
The failed candidate's loaded policy lacks execution of the fixed `mount`
helper and persistent-filesystem remount permission. The pinned status path's
`sysroot_is_read_only`/`open_dir_remount_rw` functions require these in its
private namespace. `mount_exec` keeps the helper in the daemon domain, and
`fs_remount_xattr_fs` permits this documented preparation. Linux capability
bounds and systemd protections remain unchanged; acceptance still requires
global root/sysroot read-only before and after faults. Loaded-policy checks
additionally reject generic `cert_t` file reads and raw fixed-disk reads, which
can bypass file-level SELinux protections. No raw-disk read interface is used.

Clean candidate 12 removed those denials but exposed libostree's sysroot-lock
creation in the physical `/ostree` directory, labeled `usr_t`. The installed
[libostree lock path](https://github.com/ostreedev/ostree/blob/v2026.4/src/libostree/ostree-sysroot-private.h)
is `ostree/lock`; libglnx creates, locks and unlinks that file. Generic `usr_t`
directory writes would also cover deployment/repository directories, so they
are not granted. The image policy defines a dedicated physical-directory type,
retaining Fedora's public base-directory readers, and a separate lock-file type.
A named transition selects only `lock` for callers in that directory; the
daemon can create/use/unlink that type but cannot create files of the parent
type or write generic `usr_t` directories/files.

The pinned [bootc installer](https://github.com/bootc-dev/bootc/blob/v1.16.10/crates/lib/src/install.rs)
bootstraps `/ostree` using the `/usr` label and preserves existing labels during
its final pass. For hardening images, the maintained disk entry point therefore
uses Image Builder's generated manifest with the same pinned OSBuild runtime,
adding one standard `org.osbuild.selinux` stage after installation. It applies
only the source image's `/ostree` directory context to the physical directory,
before qcow2 export. All original stages, partitions and deployment contents
are retained; original pre-hardening images keep their prior build path.
Direct OSBuild execution reproduces the pinned CLI's
[container setup](https://github.com/osbuild/image-builder/blob/50cdd3fbc2940f5ddf877dfd9033423c9ce6e1ca/pkg/setup/setup.go):
the disposable xattr-capable cache volume and a tmpfs-backed `install_exec_t`
OSBuild entry point. This build-only transition allows image contexts unknown
to the enforcing host; it does not load the image policy into the host or add
runtime daemon privileges. Native probes demonstrated both the overlay-store
failure and successful storage after this setup. Offline inspection uses
read-only `debugfs` to retrieve the raw ext4 xattr, because an ordinary host
reader presents an unknown image context as `unlabeled_t`.
The generated and final manifests, source context, offline xattr check and
runtime directory label are preserved as evidence. There is no first-boot
relabel, guest repair or manual policy loading. Loaded-policy checks reject
generic `usr_t` directory writes and parent-type file creation, and require the
named lock transition. Fedora's `auth_read_passwd_file` and
`mount_read_pid_files` interfaces permit the observed public passwd/group and
libmount-cache reads. The broader optional SSSD IPC interface is not used.

## Read-only health and incidental backend lookups

Candidate 16 completed disk construction, offline inspection and physical-label
verification, but its clean first status returned `HealthUnavailable`.
Systemd 259.8's [property filter](https://github.com/systemd/systemd/blob/v259.8/src/core/dbus.c)
requires SELinux `status` permission separately from D-Bus message exchange.
`init_status` grants public system/service status observations, without
start/stop/reload/reboot authority. `systemd_getattr_unit_files` permits bootc's
packaged-unit presence checks: directory traversal and file metadata, without
unit contents or writes. An enforcing disposable diagnostic demonstrated
healthy status with these read-only interfaces and unchanged capability bounds
and sandboxing. That modified diagnostic is not clean acceptance.

The fixed backend additionally sets `SYSTEMD_BYPASS_USERDB=1` and
`LIBMOUNT_UTAB=/tmp/sl-platformd-utab`. Systemd's supported
[userdb bypass](https://github.com/systemd/systemd/blob/v259.8/src/shared/userdb.c)
avoids dynamic/privileged NSS userdb lookups; static public passwd/group records
remain available. Libmount's supported
[utab path](https://github.com/util-linux/util-linux/blob/v2.41.5/libmount/src/utils.c)
keeps its optional cache in the service's existing private temporary directory.
No userdb IPC or global cache-directory write permission is added. Acceptance
observes these fixed values in the real backend child alongside `OPENSSL_CONF`.
Device-name resolution requiring dynamic userdb records is outside this
status-only backend's 0.0.1 requirements.

Libostree's [repository open path](https://github.com/ostreedev/ostree/blob/v2026.4/src/libostree/ostree-repo.c)
tests `faccessat(objects_fd, ".", W_OK, 0)` and continues with a read-only
repository when denied. This query is not a write; generic `system_conf_t`
directory writes remain denied. Acceptance distinguishes this expected negative
probe only by the fixed physical objects path, observed inode/device/context,
and matching journal `_AUDIT_ID` records proving x86_64 `faccessat2`, exactly
W_OK, EACCES, the confined bootc PID and `bootc status --json` proctitle.
It retains the complete raw audit sources. Actual mutations, unmatched events,
other paths/flags and every other unexpected denial still fail. Audit JSON
preserves event IDs because printk rate limiting can omit kernel records.

These small maintained read-only interfaces and fixed environment options
preserve the platform boundary for 0.0.1. Granting generic directory writes or
privileged userdb access would expand authority unnecessarily. Retyping more
repository infrastructure or patching Fedora libraries only to suppress a
legitimate negative access query has little security return at this milestone.
A broader architectural correction requires a separate tradeoff decision;
these changes add no administrative API, Linux capability or policy-loading
permission to the product.

## Resource bounds and failure behavior

A single observation permit rejects overlapping status requests with `Busy`.
The locked zbus 5.19 zero-input dispatcher skips body validation. A small
interface wrapper rejects nonempty GetStatus signatures/bodies with the standard
`org.freedesktop.DBus.Error.InvalidArgs` before entering the generated handler;
normal routing and introspection still delegate to the generated interface.
The maintained guest wire checks require exact InvalidArgs replies as root and
a permitted nonroot client. A bounded `/proc` monitor covers the complete
DynamicUser request and proves that invalid arguments spawn no bootc child.
Generated `GetStatus() -> s` introspection stays unchanged. Candidate 04's original failures and the successful diagnostic native
wire test remain retained as evidence; no test-only library feature is needed.
Both backend streams are bounded independently to 64 KiB. An overflow promptly
returns `InvalidBackendData` and kills/reaps the child, including a writer
blocked on a full pipe. The backend deadline is 15 seconds; timeout explicitly
kills/reaps and returns `BackendTimeout`. The CLI method deadline is 25 seconds.
Focused locked native tests cover the exact output boundary, both overflowing
streams and real timeout cleanup, proving the recorded child PID is absent
after each overflow and timeout. Guest fixtures hold the real bootc child;
they do not substitute a backend to manufacture oversized output.

Candidate 17 preserved both production deadlines and the exact D-Bus policy,
but its two-vCPU TCG run exposed three test-environment assumptions. A retained
Phase 3A call returned the daemon's structured `BackendTimeout`, a later
DynamicUser call reached its client transport deadline, and transient-unit
startup outlasted a separately held backend. Adjacent root and DynamicUser
status calls succeeded, including the clean first request. Unsupported root
routing was correctly rejected by the same exact XML rule used for every
caller; widening root authorization solely to obtain application dispatcher
errors would weaken the tested policy without improving the product boundary.
Acceptance therefore records either broker or application rejection, monitors
the complete invalid-signature request independently of the 15-second held
backend, and gives the TCG guest four virtual CPUs. The image keeps the
15-second backend deadline, 25-second CLI deadline and exact-method D-Bus
authorization unchanged.

## Repeatable runtime acceptance

Use the Phase 3B mode described in `tests/boot/README.md`. It retains all 36
Phase 2B/3A checks and adds:

- Automatic image-owned entry-point/domain/module and complete sandbox checks.
- A credential-only raw D-Bus client using shipped Python/libsystemd, with
  broker-verified sender identity, exact requests,
  reply/error names and exit codes. DynamicUser output comes from journald.
  Name ownership is tested while the name is free; unsupported member,
  incorrect path/interface and invalid signature are rejected. Exact retained
  errors distinguish broker policy denial from application dispatch rejection;
  the production XML continues to admit only the supported method shape even
  for root.
- SIGSTOP of the real fixed bootc child for deterministic Busy/deadline tests,
  direct child count, context/capability/command evidence and kill/reap proof.
  Children are read across every daemon thread, including Tokio workers;
  checking only the leader thread can miss the actual backend.
- Restart during an observation, two subsequent restart cycles and healthy
  recovery. An interrupted request may return structured `ServiceUnavailable`.
- SIGSTOP of the real daemon to prove the CLI method deadline independently,
  followed by SIGCONT and bounded backend recovery.
- A valid, mode-0644 copy of release metadata labeled `shadow_t`, temporarily
  bound over the fixed metadata path only in the daemon's namespace. The actual
  daemon must return `MetadataUnavailable`, with a matching enforcing AVC;
  the image-owned configuration is then restored.
- Export of the actually loaded kernel policy for native setools analysis,
  with development tools excluded from the final image.
- Final root/nonroot status, no failed units or backend leaks, SELinux
  Enforcing, unchanged deployment, composefs/sysroot read-only and EROFS writes.

The boundary client is fixed Python source in the existing test credential,
using the image's runtime libsystemd; no test binary is injected or installed.
Its ABI follows the upstream [sd-bus declarations](https://github.com/systemd/systemd/blob/main/src/systemd/sd-bus.h).
Test credentials and transient unit configuration exist only in the disposable
acceptance overlay; the underlying newly built image supplies all production
binaries, labels, policy and automatic startup. No accounts, passwords,
SSH service or production test endpoint are installed. Test changes are restored
without masking or resetting unrelated failed services. Logs, exact commands,
policy analysis and machine-readable evidence are ignored under
`image/build/output/`. Failed diagnostic overlays are evidence, not acceptance.

The pinned base supplies `service.d/10-timeout-abort.conf`; acceptance requires
that exact image-owned generic drop-in rather than an empty `DropInPaths`, and
rejects residual test overrides. The ownership negative test scopes broker
audit collection while the name is free. Its expected `USER_AVC acquire_svc`
identifies the broker PID; separate raw request/journal evidence proves the
unauthorized client UID. It is distinguished from the metadata negative test's
daemon `read` AVC and from unexpected denials.

Clean candidate 03 reproduced the inherited UDisks startup timeout during cold
TCG service activation. `image/platform/udisks2-polkit.conf` adds only
`Requires=polkit.service` and `After=polkit.service`, so its authorization
manager starts before the disk manager spends its startup budget. Neither
service is masked or reset, and their security settings/timeouts are preserved.
Fresh-image acceptance must still prove zero failed units; this ordering
correction is not a failure waiver.

Candidate 08's disk construction completed but offline inspection encountered
blank filesystem properties from udev on a reused loop device. Direct read-only
probes found valid FAT/ext4 filesystems. `inspect-qcow2.sh` now uses
`lsblk --properties-by blkid` for both diagnostic and machine-readable listings,
keeping all disk/deployment assertions and read-only mount options unchanged.

Candidate 18 passed the complete corrected evaluator under two-vCPU KVM,
114/114 checks. Its preserved four-vCPU and two-vCPU TCG runs demonstrated the
same authorization, timeout, cleanup and eventual recovery behavior, but missed
timing-sensitive recovery checks under emulation. The unchanged image completed
those paths under KVM with comfortable deadline margin.

These checks cover the current status-only API. They do not authorize or prove
future administrative operations. Standard D-Bus introspection/Peer behavior is
not a platform mutation. External connectivity and Secure Boot remain untested;
inherited Fedora warnings and composefs `verity=false` remain known limitations.
Each run reports its actual ACPI shutdown result separately.
