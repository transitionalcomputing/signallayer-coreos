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
