# SignalLayerIT CoreOS

SignalLayerIT CoreOS is the minimal, immutable operating-system substrate for
SignalLayerIT application operating systems such as CloudOS, JumpOS, and future
SignalLayer platforms.

CoreOS provides the secure, predictable, recoverable, hardware-facing platform
beneath higher-level SignalLayer operating environments.

> CoreOS should be invisible when it works, obvious when it fails, and trivial
> to recover.

## Status

**Version:** 0.0.1
**Release designation:** Developer Preview
**Platform API version:** 0.1
**Status schema:** 0.2

Validated v0.0.1 capabilities:

- OCI-native bootc system image
- bootable x86_64 qcow2 validated with UEFI and KVM
- systemd and NetworkManager networking
- immutable, read-only system root
- confined `sl-platformd` system service
- `corectl status` with machine-readable status schema 0.2
- root-only `corectl update` staging
- root-only `corectl rollback` selection
- complete fresh A -> staged B -> booted B -> offline rollback -> exact A lifecycle
  validated under KVM

`sl-platformd` exposes read-only platform status and root-only requests to
stage the configured bootc image or select the retained rollback deployment
for the next boot. Activation requires an ordinary operator-controlled reboot;
automatic reboot and automatic rollback are not implemented.

The v0.0.1 qcow2 retains the validated
`localhost/signallayer-coreos:0.0.1` bootc origin. Lifecycle acceptance exposes
a local development registry through a disposable test fixture. Public registry
origin configuration, TLS and authentication are not validated in this release.
Treat v0.0.1 as a Developer Preview rather than a turnkey Internet-updating
appliance.

## Architecture

CoreOS owns the machine.

SignalLayer OS flavors own the user experience.

CoreOS is responsible for capabilities such as:

- kernel, firmware, and hardware support
- boot infrastructure
- networking
- device and audio plumbing
- system services
- security infrastructure
- update and rollback mechanisms
- recovery
- platform APIs
- flavor and session infrastructure

Applications and user-facing workflows belong to operating-system flavors rather
than CoreOS itself.

See:

- [`docs/philosophy.md`](docs/philosophy.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/platform-api.md`](docs/platform-api.md)
- [`docs/flavor-contract.md`](docs/flavor-contract.md)
- [`docs/platform-status.md`](docs/platform-status.md)
- [`docs/platform-hardening.md`](docs/platform-hardening.md)
- [`docs/update-staging.md`](docs/update-staging.md)
- [`docs/update-activation.md`](docs/update-activation.md)
- [`docs/rollback.md`](docs/rollback.md)
- [`image/build/README.md`](image/build/README.md)
- [`tests/boot/README.md`](tests/boot/README.md)
- [`docs/releases/0.0.1.md`](docs/releases/0.0.1.md)

## Repository Layout

```text
signallayer-coreos/
├── Cargo.toml
├── Containerfile
├── README.md
├── crates/
│   └── protocol/
├── docs/
│   ├── architecture.md
│   ├── philosophy.md
│   ├── platform-api.md
│   ├── platform-status.md
│   ├── update-staging.md
│   ├── update-activation.md
│   ├── rollback.md
│   └── releases/
├── platformd/
├── sessiond/
├── corectl/
├── config/
│   ├── systemd/
│   ├── sysctl/
│   └── security/
├── image/
│   ├── build/
│   └── platform/
├── tests/
│   ├── boot/          lifecycle acceptance runners
│   ├── update/
│   └── rollback/
└── flavors/
    └── example/
```

## License

SignalLayerIT CoreOS is licensed under the Mozilla Public License 2.0
([MPL-2.0](LICENSE)).
