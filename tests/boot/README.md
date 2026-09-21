# Phase 2B: first boot

Run on `slit-coreosdev-01` (native Fedora 44 x86_64), from the same working
tree used for Phase 2A. Use a qcow2 that passed `image/build/inspect-qcow2.sh`.
The source release, `source-image.json` and `source.oci.tar` from that build
must be beside the disk, or supplied with `--source-release`, `--source-image`
and `--source-archive`.

```bash
sudo python3 tests/boot/boot-qcow2.py \
  image/build/output/COREOS_BUILD_DIRECTORY/signallayer-coreos-0.0.1-x86_64.qcow2 \
  --ovmf-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --ovmf-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --timeout 300
```

Select the actual matching OVMF code/variable templates installed on the host.
Requirements are Python 3, `qemu-system-x86_64`, `qemu-img`, OVMF and access
to `/dev/kvm`. KVM is the default. `--accel tcg` is an explicit fallback on
native x86_64 Linux and must be reported as a limitation. No host bridge,
port forwarding or listening network service is created. QEMU user networking
provides a private development NIC, DHCP and a default route through NAT;
outbound traffic can use the host connection. The test does not
prove external network access or change guest networking policy.
Restricted slirp mode deliberately omits the DHCP gateway/DNS options, so
the runner uses normal user networking without any forwarded ports.
See the upstream [DHCP implementation](https://raw.githubusercontent.com/qemu/libslirp/master/src/bootp.c).
On this builder the initial TCG attempt reached the installed system but
exceeded 300 seconds. Use `--accel tcg --timeout 900` when KVM is unavailable.

Each run creates an ignored `image/build/output/phase2b-*` directory with the
exact QEMU argument vector/command, QEMU version, firmware paths/checksums,
source qcow2 checksum/metadata, disposable boot overlay, private variable
store, serial log, QEMU stdout/stderr, QMP responses and guest evidence in
both TSV and JSON. `report.json` records checks, errors and PASS/FAIL. The
original qcow2 remains unchanged and its checksum is rechecked after stopping
QEMU. Boot writes belong to the overlay, which deliberately depends on that
original disk; preserve both when retaining a runnable test artifact.
The runner verifies the exported OCI manifest and config hashes, requires
that config to match the Phase 2A immutable source image ID, and compares
the running bootc digest with this archive manifest. OCI export can change
the original Podman manifest digest without changing the image config ID.

The probe uses existing systemd
[hypervisor credentials](https://systemd.io/CREDENTIALS/) and
[temporary unit support](https://github.com/systemd/systemd/blob/v259/man/systemd-debug-generator.xml).
QEMU supplies a transient service, a dependency from `multi-user.target` and
the probe script via SMBIOS. Units and credentials exist in `/run` for this
test boot. The service is excluded from the initrd and runs after the normal
operational target. No login account, password, SSH service or image change
is required. Evidence returns through a dedicated virtio serial port.
Command output is captured through pipes, with the evidence descriptor closed
in child commands, so confined SELinux domains need no new file permissions.

PASS requires PID 1 systemd, active `multi-user.target`, a running system
without failed units, active NetworkManager with a global IPv4 address and
default route, the expected bootc/OSTree booted deployment and source manifest
digest, exact source
release metadata, enforcing SELinux, composefs evidence and read-only `/`
and `/sysroot` mounts. Both `/` and `/usr` must reject a test write with
EROFS; an unexpectedly successful marker is immediately removed and fails
the test. Mount/configuration and preparation journal data are preserved so
failures can be diagnosed without relaxing root or SELinux settings.

The host enforces a boot timeout, requests ACPI shutdown through QMP once
evidence is complete, and stops its QEMU process on failure or timeout.
Shutdown status is recorded separately from boot checks. No update, rollback
or platform-service validation is performed.

For Phase 3A, add `--phase3a` to the same boot command (use `--timeout 1800`
on the TCG-only development host). This appends the temporary platform probe
and checks the real daemon, human/JSON CLI, DynamicUser access, service/backend
errors and final restored health while retaining the original 18 checks.
See [the status contract](../../docs/platform-status.md). Evidence is saved in
an ignored `image/build/output/phase3a-*` directory.

For Phase 3B, retain all Phase 3A checks and add actual enforcing-domain,
D-Bus boundary, concurrency/deadline, negative confinement and restart tests:

```bash
# Native policy analysis tools remain outside the final image.
sudo podman build --target policy-tools -t localhost/slit-policy-tools:phase3b .

sudo python3 tests/boot/boot-qcow2.py \
  image/build/output/COREOS_BUILD_DIRECTORY/signallayer-coreos-0.0.1-x86_64.qcow2 \
  --phase3b \
  --policy-tools-image localhost/slit-policy-tools:phase3b \
  --ovmf-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --ovmf-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --accel kvm --cpus 2 --timeout 1800
```

Run the OCI build/lint and existing disk build/offline inspection before the
boot command. Use truthful build metadata and a distinct Phase 3B image tag;
preserve earlier disk/source artifacts. The fixed boundary client uses the
image's existing Python and libsystemd through the test credential. No native
test executable, policy, or file-label repair is injected into the final guest.
The script records exact requests and error names, verifies the broker-reported
sender UID against its own UID, and is matched against DynamicUser journal
credentials. The image must supply the daemon, policy and labels automatically.
Candidate 18's final acceptance topology is two vCPUs with KVM acceleration.
TCG remains useful for diagnostics, but its preserved runs showed timing
sensitivity in recovery checks. Do not weaken the production 15-second backend
or 25-second client deadline to accommodate TCG scheduling overhead.

Each ignored `image/build/output/phase3b-*` run includes all prior evidence,
exact collected guest command strings, security requests/UIDs/error names,
held real backend PID/context/capabilities, cleanup/deadline/restart results,
expected negative AVC and final restored state. The actually loaded kernel
policy is compressed across the evidence port and analyzed in the native
tools container with networking disabled. `loaded-policy.bin` and
`policy-analysis.json` retain the queried policy and exact queries/results.
See [the hardening boundary](../../docs/platform-hardening.md).

All guest changes are temporary fixtures on the disposable overlay: name-free
ownership tests stop/restart the daemon; real child SIGSTOP holds observations;
a stopped daemon tests the CLI method deadline; the `shadow_t` metadata bind
is removed and the original image-owned unit restored. Do not weaken SELinux
or the sandbox to accommodate a test. Do not count a diagnostic policy overlay
as fresh-image acceptance. Report the observed ACPI shutdown independently.

Audit collection includes JSON with systemd `_AUDIT_ID` values. The expected
negative tests remain required. A separate expected repository-writability
probe must correlate the observed `/sysroot/ostree/repo/objects` inode, device
and label with a denied x86_64 `faccessat2(W_OK)` event and fixed status
proctitle. No actual write or unmatched denial is excluded, and loaded-policy
analysis requires generic configuration-directory writes to remain denied.
Held-child evidence also requires the fixed OpenSSL, static-userdb and private
libmount-cache environment values. See the proportionality rationale in the
hardening document.

For Phase 3C, build a fresh qcow2 that passed the normal offline inspection,
keep the next image available from the host registry on port 5000, and run:

```bash
sudo python3 tests/boot/boot-update-qcow2.py \
  image/build/output/COREOS_BUILD_DIRECTORY/signallayer-coreos-0.0.1-x86_64.qcow2 \
  --ovmf-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --ovmf-vars /usr/share/edk2/ovmf/OVMF_VARS.fd \
  --timeout 900
```

The dedicated KVM runner first proves that a bounded failed update leaves the
running deployment healthy. It then exposes the host registry only through a
disposable guest-local proxy and invokes the fixed `corectl update` path. PASS
requires a prompt D-Bus response, a concurrent `Busy` result, the exact fixed
unit command, Fedora's `install_t` bootc transition, successful A-to-B staging
with `downloadOnly=false`, an unchanged boot ID, no reboot, enforcing SELinux,
and the original immutable-root guarantees. Artifacts are retained under an
ignored `image/build/output/phase3c-acceptance-*` directory. See
[the update-staging contract](../../docs/update-staging.md).

For Phase 3D, keep the accepted Phase 3C qcow2 as deployment A and publish a
distinct image B containing the same accepted platform stack to the existing
host test registry. Run `boot-activate-qcow2.py` with the same firmware paths.
The runner uses one KVM process and one disposable overlay. Its guest probe
stages B through `corectl update`, records both identities, requests one normal
`systemctl reboot`, verifies B after the machine returns, and powers off after
collecting health and retention evidence. The resulting ignored
`phase3d-acceptance-*` directory retains the B-active/A-retained overlay for
Phase 3E together with machine-readable evidence. See
[the activation contract](../../docs/update-activation.md).
