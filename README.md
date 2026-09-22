# SignalLayer CoreOS

SignalLayer CoreOS is the minimal, immutable operating-system substrate beneath
SignalLayer operating-system flavors such as CloudOS and JumpOS. It owns the
hardware-facing platform, deployment lifecycle, security boundary, and narrow
platform capabilities; flavors own applications and the user experience.

> CoreOS should be invisible when it works, obvious when it fails, and trivial
> to recover.

## Developer Preview

**SignalLayer CoreOS 0.0.1 is a Developer Preview, not a production-ready
release.** The validated platform is x86_64 QEMU/KVM with OVMF UEFI. Secure
Boot, physical hardware, and other architectures were not validated.

The release implements an OCI-native bootc system image, a bootable qcow2,
read-only platform status, update staging, explicit-reboot activation, and
manual rollback selection. It does not provide an installer, login/password/SSH
provisioning, a production update-registry configuration, automatic reboot, or
automatic rollback.

## Download 0.0.1

The [v0.0.1 GitHub Release](https://github.com/transitionalcomputing/signallayer-coreos/releases/tag/v0.0.1)
contains the published artifacts:

| Artifact | Purpose |
| --- | --- |
| [`signallayer-coreos-0.0.1-x86_64.qcow2`](https://github.com/transitionalcomputing/signallayer-coreos/releases/download/v0.0.1/signallayer-coreos-0.0.1-x86_64.qcow2) | Bootable x86_64 evaluation disk for QEMU/KVM with OVMF UEFI |
| [`signallayer-coreos-0.0.1-x86_64.oci.tar`](https://github.com/transitionalcomputing/signallayer-coreos/releases/download/v0.0.1/signallayer-coreos-0.0.1-x86_64.oci.tar) | OCI archive containing the bootc system image |
| [`SHA256SUMS`](https://github.com/transitionalcomputing/signallayer-coreos/releases/download/v0.0.1/SHA256SUMS) | SHA-256 integrity values for release files |
| [`PROVENANCE.md`](https://github.com/transitionalcomputing/signallayer-coreos/releases/download/v0.0.1/PROVENANCE.md) | Source, builder, artifact identity, and final validation record |

Release artifacts are not cryptographically signed. Verify the downloaded
qcow2 or OCI archive against `SHA256SUMS`, then see
[Evaluate 0.0.1](docs/evaluating-0.0.1.md) for the intentionally limited public
evaluation workflow.

## Implemented in 0.0.1

- OCI-native bootc system image and bootable x86_64 qcow2.
- UEFI boot under QEMU/KVM into systemd with NetworkManager networking.
- Immutable, read-only system root with composefs enabled.
- Confined `sl-platformd` and `corectl status`, using Platform API version 0.1
  and status schema 0.2.
- Root-only `corectl update` staging through a fixed systemd worker.
- Explicit operator reboot into the staged deployment.
- Root-only `corectl rollback` selection of the retained deployment, followed
  by an explicit operator reboot.
- A complete fresh A -> staged B -> booted B -> offline rollback -> exact A
  lifecycle validated under genuine KVM.

The platform boundary is `corectl` -> system D-Bus -> confined `sl-platformd`
-> fixed systemd workers -> bootc. Mutation requests accept no caller-controlled
command, unit name, or bootc argument.

The qcow2 retains `localhost/signallayer-coreos:0.0.1` as its bootc origin.
Lifecycle validation used a local development registry fixture; public registry
origin configuration, TLS, and authentication were not validated. See the
[0.0.1 release notes](docs/releases/0.0.1.md) for the complete release boundary.

## Documentation

| Start with | Description |
| --- | --- |
| [Evaluate 0.0.1](docs/evaluating-0.0.1.md) | Choose, verify, and minimally boot the published Developer Preview artifacts |
| [0.0.1 release notes](docs/releases/0.0.1.md) | Validated capabilities, artifact identities, and limitations |
| [0.0.1 provenance](docs/releases/0.0.1-provenance.md) | Final source, build, artifact, and validation identities |

Deeper technical documentation:

- [Architecture](docs/architecture.md) and
  [design philosophy](docs/philosophy.md)
- [Platform API](docs/platform-api.md), including the distinction between the
  implemented 0.0.1 surface and the forward-looking API design
- [Current status schema and behavior](docs/platform-status.md)
- [Platform hardening and SELinux boundary](docs/platform-hardening.md)
- [Update staging](docs/update-staging.md),
  [update activation](docs/update-activation.md), and
  [manual rollback](docs/rollback.md)
- [Flavor contract](docs/flavor-contract.md)

Engineering references for building and acceptance testing remain in
[`image/build/README.md`](image/build/README.md) and
[`tests/boot/README.md`](tests/boot/README.md). They document the release's
engineering process, not the public evaluation path.

## Repository layout

```text
signallayer-coreos/
├── crates/             shared protocol definitions
├── corectl/            platform command-line client
├── platformd/          privileged platform service
├── sessiond/           session-service foundation
├── config/             systemd, D-Bus, and security configuration
├── docs/               architecture, API, lifecycle, and release documentation
├── image/              image definition and build engineering
├── tests/              native and VM acceptance tooling
└── flavors/            example flavor material
```

## License

SignalLayer CoreOS is licensed under the
[Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).
