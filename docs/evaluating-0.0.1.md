# Evaluate SignalLayer CoreOS 0.0.1

SignalLayer CoreOS 0.0.1 is a Developer Preview for technical evaluation. It
is not an installer image or a production-ready operating-system release.

This guide covers only the published artifacts and a minimal boot. The internal
acceptance harness is documented separately in
[`tests/boot/README.md`](../tests/boot/README.md); reproducing that harness is
not required for a first evaluation.

## Choose an artifact

Download files from the
[v0.0.1 GitHub Release](https://github.com/transitionalcomputing/signallayer-coreos/releases/tag/v0.0.1).

| Artifact | Use it when you want to |
| --- | --- |
| `signallayer-coreos-0.0.1-x86_64.qcow2` | Boot the Developer Preview under x86_64 QEMU/KVM with OVMF UEFI |
| `signallayer-coreos-0.0.1-x86_64.oci.tar` | Inspect or import the OCI-native bootc system image |
| `SHA256SUMS` | Verify downloaded content against the published SHA-256 values |
| `PROVENANCE.md` | Review source, builder, image, firmware, artifact, and validation identities |

The OCI archive is the system-image payload, not a conventional VM disk. Use
the qcow2 for the minimal boot below.

## Verify the download

The release artifacts are not cryptographically signed. SHA-256 verifies that a
download has the published content; it does not authenticate the publisher.

On a system with GNU `sha256sum`, calculate the digest of whichever payload
you downloaded:

```bash
sha256sum signallayer-coreos-0.0.1-x86_64.qcow2
sha256sum signallayer-coreos-0.0.1-x86_64.oci.tar
```

Compare the result with the matching entry in the published `SHA256SUMS`:

| Artifact | Expected SHA-256 |
| --- | --- |
| qcow2 | `a533d14420ad0483090d98b117bc5dd042d9bab9af46bf0e9a2aec8ef7740fa7` |
| OCI archive | `98b92981e019dd3c32ef589fcc07847c13f1c6dc73d3ed3d9bc9fc5a2c67b7a1` |

On macOS, the equivalent calculation is `shasum -a 256 FILE`. The qcow2
itself was validated only on x86_64 Linux with KVM and OVMF.

## Minimally boot the qcow2

The validated environment was x86_64 QEMU/KVM, the Q35 machine model, and OVMF
UEFI firmware. Firmware filenames and locations vary by Linux distribution.
Identify the matching OVMF code and variable-template files installed on your
host before running QEMU.

Work on copies so evaluation writes do not modify the downloaded disk or the
firmware variable template:

```bash
cp signallayer-coreos-0.0.1-x86_64.qcow2 \
  signallayer-coreos-0.0.1-x86_64.eval.qcow2
cp /path/to/OVMF_VARS.fd ./OVMF_VARS.eval.fd

qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -smp 2 \
  -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file=/path/to/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=./OVMF_VARS.eval.fd \
  -drive if=none,id=os,format=qcow2,file=./signallayer-coreos-0.0.1-x86_64.eval.qcow2 \
  -device virtio-blk-pci,drive=os \
  -nic user,model=virtio-net-pci \
  -nographic
```

This is a minimal observation-oriented boot, not the project's acceptance
procedure. The image is configured for serial-console output. QEMU's
`Ctrl-A X` escape exits a `-nographic` session.

### What to expect

- The machine should reach the installed system under systemd.
- NetworkManager, DHCP, a guest address, and a default route were validated with
  QEMU user networking. Broad Internet and DNS behavior are not guaranteed.
- **No login, password, or SSH access is provisioned.** Reaching a login prompt
  does not imply that there is a credential to use. The release intentionally
  has no general interactive evaluation account.
- The qcow2 is an evaluation/development artifact. There is no 0.0.1 installer
  or production provisioning workflow.

The absence of a login is why this guide does not instruct an evaluator to run
`corectl` inside the stock disk. The release's status, update, rollback,
security, and lifecycle claims were exercised by ephemeral test credentials in
the acceptance harness without adding an account to the image.

## Important lifecycle boundary

The qcow2's bootc origin is
`localhost/signallayer-coreos:0.0.1`. Update and rollback lifecycle validation
used a local development registry arrangement. A production/public registry
origin, TLS, and authentication were not validated for 0.0.1.

Updates are deployment-based:

1. A root-authorized operator stages an update.
2. The running deployment remains active.
3. An explicit operator reboot activates the staged deployment.
4. Rollback selection is manual and also requires an explicit reboot.

There is no automatic health-triggered rollback, boot-attempt rollback policy,
or separate recovery environment in this release.

## Continue reading

- [Release notes and full limitations](releases/0.0.1.md)
- [Release provenance](releases/0.0.1-provenance.md)
- [Architecture](architecture.md)
- [Platform API: implemented surface versus forward design](platform-api.md)
- [Current status behavior and schema 0.2](platform-status.md)
- [Security and SELinux boundary](platform-hardening.md)
- [Update staging](update-staging.md) and
  [activation](update-activation.md)
- [Manual rollback](rollback.md)
- [Flavor contract](flavor-contract.md)
