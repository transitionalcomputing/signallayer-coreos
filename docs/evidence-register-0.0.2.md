# SignalLayer CoreOS 0.0.2 evidence register

This register records where accepted 0.0.2 runtime evidence is preserved
and what it demonstrates. Evidence is preserved, not regenerated: accepted
runs are never rerun for archival purposes.

## Storage

Each location holds identical copies, verified by sha256:

- Dev build VM: `signallayer-evidence/` in the build user's home, covered
  by the hypervisor's VM backups.
- Maintainer workstation: `SignalLayer-Evidence/`, outside any repository.
- The original run directories remain in place under the builder's
  `image/build/output/`.

Per-file checksums: `docs/evidence/*.sha256`.

The dev VM and workstation copies also hold `base/`, the base disk images
that the run overlays are backed by. On the builder, the original base
disks remain in their build directories under `image/build/output/`.

## Phase 4A

Contract and architecture work only. No runtime evidence is expected.

## Phase 4B

Preserved run: `phase4b-4v9xxyou` (2026-09-23).

## Phase 4C

Accepted run: `phase4c-6pelg71t` (2026-09-24, KVM).

Artifact linkage, recorded in the run:
- built disk (base image) sha256 `04d00c597249cd4884b2c4f6b13f25f401e7685a4f82da1d61b721e94923cd4d`;
  the run's `boot.qcow2` is a per-run overlay backed by this disk
- OCI config `282d65963edc8405eda58bc33ef2929c7d71c31f4aa2b5ec09f20d3e66815a55`
- image release metadata: `SOURCE_REVISION=5b29ee62e2b0e61345da87423e23a3a685f25028-dirty`,
  `BUILD_ID=0.0.2-phase4c-boundary`

Source provenance: `SOURCE_REVISION` was a manually supplied build argument
recording the original 4C head plus uncommitted changes. The builder tree
was compared file by file against `94548e6401bcba841996e70510cfeaea0b976fd0`:
all 76 image-affecting tracked files match. The only two differing files are
test-harness files that do not enter the image (`tests/boot/boot-qcow2.py`,
`tests/boot/guest-session-probe.sh`). macOS AppleDouble files present in the
build context cannot reach the final image. No builder file has a
modification time after the build started. For the source content that could affect the
image, the accepted build is content-equivalent to `94548e6`.

Result: the original evaluator reported FAIL, 63/69. With Andie's explicit
approval, the preserved evidence was re-evaluated without any rerun. Three
failures were evaluator or sequencing artifacts, including an evaluator
defect since corrected in `94548e6`, and were resolved as passes from the
preserved evidence. Three were excluded from the required set. Recorded
re-evaluated result: `PASS_REEVALUATED`, 66/66 checks in the revised
required set; this does not imply that the three excluded checks were
demonstrated by the 4C runtime.

Disposition of the excluded checks:
- `session_platform_restored`, `session_evidence_valid`: not demonstrated by
  the 4C runtime, because the probe exhausted systemd's start limit before
  the recovery check. 4C acceptance remains valid; these two Session
  recovery properties are carried forward to 4D acceptance rather than
  retroactively claimed as proven.
- `management_no_phase4d_api`: closed from source. `94548e6` contains no
  `StartReboot`, reboot worker, or reboot unit, and reports Platform API 0.1.

Also preserved: `phase4c-twoa1a4v` (2026-09-24), an earlier 4C run.

Rescued artifacts: five Phase 4C harness and source bundles preserved from
non-durable temporary storage, listed in
`docs/evidence/rescue-2026-09-24.sha256`.

## Phase 4D

Accepted run: `phase4d-6pj9cknl` (2026-09-25, KVM), PASS, 92/92 required
checks.

- Product commit: `afbc043fdf707d3da80e1a8c47d62b0958cf0598` (tree
  `d976fe5e8712eedfb271fdd2cb187675a9e9d733`, clean).
- Harness commit: `7f7b40151a240145a581eb0a74d251dc568f84d9` (tree
  `c6c3072040c131aa7902aeb61c8d48a1f0f304fc`, clean). It changes only
  `tests/boot/` relative to the product commit.
- Acceptance qcow2 sha256:
  `d005ba25943084f0f87346ac9dd5461da8ad21c4c866427162ee0acdf1b41a95`.
- OCI image ID and config digest:
  `7f08142468fbaf2ad3545ac3d2f504153e04803d66b077aa80eadfde613cb33e`.
- Base: registry pin
  `quay.io/fedora/fedora-bootc@sha256:38ef702a1366d4ae6645dbe77192fe50f91dce487e6c6fffc046f9ad7e9ffa74`;
  local image ID
  `fd0afe29ae8ee618a20265a81d5d9ec6b032fc8912eb91a420082a197081360b`.

The run confirmed Platform API 0.2 and status schema 0.3. A non-root
`StartReboot` from the `sl-sessiond` UID was denied with
`org.freedesktop.DBus.Error.AccessDenied`. `corectl reboot` was accepted
(exit 0), and QMP logged exactly one reset. BOOT_2 had a new boot ID linked to
BOOT_1, with the booted deployment and update/rollback state unchanged, SELinux
Enforcing and no failed units. The 4C Session recovery checks carried forward
to 4D, `session_platform_restored` and `session_evidence_valid`, now pass.

Superseded run: `phase4d-djguo10v` (FAIL, preserved), built from and tested at
the product commit. Its only failed check, `post_platform_session_agree`,
compared two non-atomic live reads: the later Session1 read included an IPv6
address and gateway absent from the earlier Platform read, consistent with IPv6
autoconfiguration still converging (inferred, not established by the evidence). The contract does not promise atomic reads across consumers. The harness
now requires a converged Platform, Session1, Platform read. The rerun used the
same acceptance qcow2, verified unchanged before and after.

Storage: the dev VM (`phase4d-b/` and `phase4d-b2/`, with `4db.log` and
`4db2.log`), the maintainer workstation, and the hypervisor's VM backups.
Per-file checksums: `docs/evidence/phase4d-6pj9cknl.sha256` and
`docs/evidence/phase4d-djguo10v.sha256`.

## Base disks

Each preserved run's `boot.qcow2` is a per-run overlay. The base disk
images the overlays are backed by are preserved separately under
`base/`, with checksums in `docs/evidence/base-disks.sha256`.

| Base disk (build directory) | Backs the overlay of | sha256 |
|---|---|---|
| `coreos-0.0.1-x86_64.EYpVNzah` | `phase4c-6pelg71t` (accepted 4C run) | `04d00c597249cd4884b2c4f6b13f25f401e7685a4f82da1d61b721e94923cd4d` |
| `coreos-0.0.1-x86_64.KopgVifu` | `phase4c-twoa1a4v` | `1221d1fed98dc7af17225371cd627dc80edfda062e3592e64e333698ceb69576` |
| `coreos-0.0.1-x86_64.o8GpB5fx` | `phase4b-4v9xxyou` | `c3911952b5d4e52bbf03ddeb2d24c84fe65f952e36c0287b0f27a4c3187981fd` |

Archived run overlays reference their original absolute backing
paths. To inspect one after relocation, rebase a copy of the overlay
onto the archived base disk with `qemu-img rebase -u`. Never rebase
the preserved overlay itself.
