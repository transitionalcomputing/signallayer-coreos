# Base images

SignalLayer CoreOS builds from a Fedora bootc base pinned by digest. Upstream
registries stop serving old digests: the 0.0.2 base
(`quay.io/fedora/fedora-bootc@sha256:38ef702a…`) had already been removed from
Quay by 2026-09-25. Bases are therefore mirrored to
`ghcr.io/transitionalcomputing/fedora-bootc`, and every base is recorded here.

## Refresh procedure

1. **Resolve** the upstream tag to digests. Record the index digest and the
   `linux/amd64` manifest digest:
   `skopeo inspect --raw docker://quay.io/fedora/fedora-bootc:<tag>`.
2. **Copy** the whole index, unchanged, to the mirror:
   `skopeo copy --all --preserve-digests docker://quay.io/fedora/fedora-bootc@<index digest> docker://ghcr.io/transitionalcomputing/fedora-bootc:<tag>-<YYYYMMDD>`.
3. **Verify** that the mirror's index digest equals the upstream index digest,
   and that the `linux/amd64` manifest digest is present in the mirrored index.
4. **Pin** every Containerfile `FROM` to the mirror's `linux/amd64` manifest:
   `ghcr.io/transitionalcomputing/fedora-bootc@<amd64 manifest digest>`.
5. **Record** the base in the register below.
6. **Never delete** old bases or their mirror tags. Validated releases must
   stay rebuildable from the exact base they used.

## Register

### 0.0.2 base (historical)

- **Upstream pin:** `quay.io/fedora/fedora-bootc@sha256:38ef702a1366d4ae6645dbe77192fe50f91dce487e6c6fffc046f9ad7e9ffa74`,
  the `linux/amd64` manifest. It was no longer served by Quay on 2026-09-25,
  and neither was the index digest recorded with it
  (`sha256:111e3195e9c96e74c2516d6b2f5114ede06449a6a5910cbd9dd9e5e0f52037af`).
- **Local image (config) ID:** `fd0afe29ae8ee618a20265a81d5d9ec6b032fc8912eb91a420082a197081360b`,
  preserved in the build host's root container storage and as an OCI archive
  in the evidence archive (`base-image/`).
- **GHCR archive copy:** `ghcr.io/transitionalcomputing/fedora-bootc:0.0.2-base`.
  This is a SignalLayer-preserved copy of the local image, pushed from
  container storage. Its manifest digest is **not** the Quay digest above,
  because the original registry manifest could not be recovered. It is
  identified by its config digest, which must equal the local image ID.
  - Config digest: `sha256:fd0afe29…` (verified at push).
  - GHCR manifest digest: *filled in after the 5A run*.

### Fedora 44 base (from 5A)

- **Upstream:** `quay.io/fedora/fedora-bootc:44`, resolved on 2026-09-26.
  - Index: `sha256:6718b0634e138d1909e752dc0f7d8a203ede6ece33bc637f72282bde3d44887b`
  - `linux/amd64` manifest: `sha256:ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c`
- **Mirror:** `ghcr.io/transitionalcomputing/fedora-bootc:44-20260926`, copied
  with `--all --preserve-digests`.
  - Index digest: expected to equal the upstream index; *confirmed after the
    5A run*.
- **Containerfile pin:** `ghcr.io/transitionalcomputing/fedora-bootc@sha256:ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c`.
