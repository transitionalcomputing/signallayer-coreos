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
**Project status:** Early development

Current prototype capabilities:

- builds as an OCI image
- converts to a bootable VM image
- boots in QEMU
- reaches networking
- runs systemd
- uses an immutable root
- exposes `sl-platformd`
- supports `corectl status`

`sl-platformd` currently exposes read-only platform status. Update and rollback
lifecycle validation is planned.

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

## Repository Layout

```text
signallayer-coreos/
├── Containerfile
├── README.md
├── docs/
│   ├── architecture.md
│   ├── philosophy.md
│   ├── platform-api.md
│   └── flavor-contract.md
├── platformd/
├── sessiond/
├── corectl/
├── config/
│   ├── systemd/
│   ├── sysctl/
│   └── security/
├── image/
│   └── build/
├── tests/
│   ├── boot/
│   ├── update/
│   └── rollback/
└── flavors/
    └── example/
