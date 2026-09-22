# SignalLayer CoreOS — Architecture

**Status:** Draft
**Version:** 0.1
**Project:** SignalLayer CoreOS

> **Document scope:** This draft records architectural boundaries and design
> direction. It is not a claim that every described capability exists in
> SignalLayer CoreOS 0.0.1. See the [0.0.1 release notes](releases/0.0.1.md)
> and [current Platform API documents](platform-api.md) for the implemented and
> validated release surface.

## Purpose

This document defines the architectural boundaries of SignalLayer CoreOS.

It describes what components exist, which responsibilities they own, how they interact, and where stable interfaces must exist.

Implementation details may evolve.

Architectural boundaries should change deliberately.

---

## System Model

SignalLayer CoreOS is the hardware-facing substrate beneath SignalLayer application operating systems.

At a high level:

```text
+------------------------------------------------------+
|               SignalLayer OS Flavor                  |
|                                                      |
|        CloudOS / JumpOS / future platforms           |
|                                                      |
|     applications / shells / workflows / UX           |
+---------------------------+--------------------------+
                            |
                  SignalLayer Platform API
                            |
+---------------------------v--------------------------+
|                SignalLayer CoreOS                    |
|                                                      |
|  sessiond     corectl       platform libraries       |
|       \          |                 /                  |
|        +---------v----------------+                   |
|              sl-platformd                            |
|                                                      |
|  update / rollback / devices / power / identity      |
|  networking / security / system policy / recovery    |
+---------------------------+--------------------------+
                            |
+---------------------------v--------------------------+
|              Linux / systemd / hardware              |
+------------------------------------------------------+
```

The primary architectural rule is:

> CoreOS owns the machine. Flavors own the experience.

---

## Architectural Layers

### 1. Hardware and Kernel Layer

This layer contains the components required to operate the physical or virtual machine.

Responsibilities include:

* Linux kernel
* firmware
* hardware drivers
* storage discovery
* networking hardware
* graphics hardware
* audio hardware
* input devices
* system clocks
* TPM and security hardware
* virtualization interfaces where applicable

Higher-level flavors should not normally need to manage hardware directly.

CoreOS should expose appropriate hardware capabilities through stable platform interfaces.

---

### 2. Base System Layer

The base system provides the minimal userspace required for CoreOS operation.

Responsibilities include:

* init and service management
* device management
* networking infrastructure
* system logging
* filesystem management
* authentication primitives
* security infrastructure
* system policy
* recovery support

The base system exists to support the platform.

It is not intended to become a traditional general-purpose Linux userspace.

---

### 3. Platform Services Layer

Platform services expose machine capabilities to higher-level components.

The primary platform authority is `sl-platformd`.

Supporting services may exist where responsibility is clearly separated, but privileged machine control should not be fragmented across unrelated daemons.

Platform services should provide capabilities through stable interfaces rather than exposing implementation details.

---

### 4. Session and Flavor Layer

The session and flavor layer manages interaction between CoreOS and the active SignalLayer operating-system flavor.

`sl-sessiond` belongs here.

Responsibilities may include:

* flavor activation
* session creation
* environment preparation
* session teardown
* flavor health monitoring
* coordination with platform services

This layer should not own machine-level privilege unless explicitly delegated through the platform interface.

---

## Deployment Model

CoreOS treats the operating system as a deployable image.

A deployment represents a known operating-system state.

The deployment layer is responsible for:

* identifying the running deployment
* retrieving new system images
* verifying system artifacts
* preparing new deployments
* selecting the next deployment
* retaining known-good deployments
* rollback
* recovery integration

Updating CoreOS means creating or activating a new deployment.

Updating CoreOS must not depend upon incrementally mutating the currently running operating system.

---

## Deployment Invariants

### Identifiable Deployment

A running CoreOS system must be attributable to a specific deployment.

An administrator must be able to determine:

* CoreOS version
* image identity
* deployment identity
* currently booted deployment
* deployment selected for the next boot
* previous known-good deployment

---

### Non-Destructive Updates

Preparing a new deployment must not destroy the currently bootable known-good deployment.

Until a new deployment has successfully booted and been accepted, rollback must remain possible.

---

### Recoverable Boot

A failed deployment must not permanently prevent access to a previously functional system.

Boot and recovery mechanisms should preserve a path back to a known-good state.

---

### Image as Source of Truth

The deployed system image defines CoreOS system software.

Installation scripts, first-boot scripts, or administrator actions must not become the authoritative definition of operating-system state.

The image should.

---

## Persistent State Model

CoreOS must explicitly classify writable persistent state.

Persistent data belongs to one of the following categories.

### Machine Configuration

Configuration describing how a particular machine should behave.

Examples may include:

* hostname
* network configuration
* enrollment information
* platform policy
* machine-specific administrative configuration

---

### Platform State

Persistent state owned by CoreOS platform services.

Examples may include:

* deployment metadata
* update state
* machine identity
* cryptographic identity
* hardware policy
* recovery metadata

---

### Flavor State

Persistent state owned by an installed SignalLayer operating-system flavor.

CoreOS may provide storage locations and lifecycle mechanisms for this state, but the contents belong to the flavor.

---

### User State

Persistent user-owned data.

User data must remain logically separate from the immutable operating-system deployment.

---

### Cache and Reconstructable State

Data that may improve performance but can be regenerated without loss of meaningful state.

Caches must never become undocumented dependencies.

---

## State Invariant

Every writable persistent location must have:

* an owner
* a purpose
* a lifecycle
* defined backup expectations where appropriate

Persistent state must not exist merely because software happened to write to a filesystem path.

The long-term goal is for CoreOS to be able to enumerate the persistent state present on a machine.

---

## Filesystem Ownership

The filesystem should clearly separate immutable operating-system content from persistent state.

The exact layout may evolve, but the ownership model should remain explicit.

Conceptually:

```text
immutable system content
    CoreOS image-owned files
    system binaries
    platform libraries
    system service definitions

persistent platform state
    machine identity
    deployment metadata
    platform configuration

persistent flavor state
    flavor configuration
    flavor-owned service state

persistent user state
    user profiles
    user files
    application data

reconstructable state
    caches
    temporary files
```

No component should gain persistence merely by choosing an arbitrary writable path.

---

## `sl-platformd`

`sl-platformd` is the privileged machine-scoped platform authority.

It owns operations that require privileged access or authoritative knowledge of machine state.

Expected responsibilities include:

* deployment inspection
* system update
* rollback
* boot-state management
* platform identity
* hardware discovery
* hardware policy
* power management
* privileged device operations
* security-sensitive platform operations
* recovery coordination

`sl-platformd` must expose capabilities rather than leaking implementation details.

For example, callers should request operations such as:

```text
Update system
Roll back deployment
Reboot machine
List devices
Get platform identity
```

rather than manipulating the underlying implementation directly.

---

## Privilege Boundary

`sl-platformd` defines an important privilege boundary.

Consumers should receive only the platform capabilities they require.

The daemon should:

* run with the minimum practical privileges
* validate every privileged request
* expose narrow interfaces
* avoid arbitrary command execution
* avoid becoming a generic privileged helper
* clearly distinguish inspection from state-changing operations
* authenticate and authorize callers where appropriate

A stable API does not imply unrestricted authority.

---

## `sl-sessiond`

`sl-sessiond` manages flavor and session lifecycle above the machine authority layer.

Expected responsibilities may include:

* flavor activation
* session creation
* session teardown
* environment preparation
* session health
* coordination between the active flavor and CoreOS

`sl-sessiond` should consume privileged capabilities through the Platform API rather than duplicating or bypassing `sl-platformd`.

It must not gradually become a second machine-management daemon.

---

## `corectl`

`corectl` is the administrative command-line interface for CoreOS.

It is a client of platform services, not the implementation of platform logic.

Routine administrative operations should include commands such as:

```text
corectl status
corectl update
corectl rollback
corectl reboot
corectl diagnostics
```

`corectl` should translate human administrative intent into stable platform API operations.

Business logic should not be duplicated between `corectl` and `sl-platformd`.

---

## SignalLayer Platform API

The SignalLayer Platform API is the stable contract between CoreOS and higher-level operating-system components.

Flavors should depend upon platform capabilities rather than CoreOS internals.

The API may eventually expose areas such as:

* system identity
* deployment state
* updates
* rollback
* power management
* devices
* hardware capabilities
* system health
* networking capabilities
* session lifecycle

The API contract is defined separately in:

`docs/platform-api.md`

---

## Flavor Boundary

A SignalLayer OS flavor provides the user-facing operating environment.

Examples include:

* CloudOS
* JumpOS
* future SignalLayer operating systems

Flavors may provide:

* applications
* graphical shells
* desktop environments
* remote-access environments
* user workflows
* product-specific services
* application policy
* presentation and branding

Flavors should not directly depend upon undocumented CoreOS implementation details.

The flavor contract is defined separately in:

`docs/flavor-contract.md`

---

## Platform Capability Rule

When a flavor needs access to machine-level functionality, the preferred sequence is:

1. determine whether the capability already exists in the Platform API
2. if it exists, use the platform interface
3. if it does not exist and is generally useful, consider adding a platform capability
4. avoid direct dependency on CoreOS implementation details

The question should be:

> What capability does the flavor need?

not:

> Which CoreOS internal file or command can the flavor manipulate?

---

## Replaceable Internals

CoreOS is the reference implementation of the SignalLayer Platform.

The stable platform boundary should make it possible, in principle, for another system to implement compatible platform services.

A compatible implementation might use a different:

* Linux distribution
* image technology
* boot mechanism
* update engine
* service implementation

A flavor should not care how the platform implements an operation when the platform contract already defines that operation.

Official SignalLayer operating-system images will use CoreOS unless another platform is explicitly promoted to supported status.

---

## Configuration Ownership

Configuration under `config/` belongs to CoreOS itself.

Current categories include:

```text
config/
├── systemd/
├── sysctl/
└── security/
```

These files define platform policy and should be incorporated into the system image during the build.

Machine-specific configuration must remain separate from image-owned policy.

---

## Image Construction

The `image/` tree contains tooling and definitions used to produce deployable CoreOS artifacts.

The resulting image, rather than an installation script, defines the operating system.

The build process should eventually provide:

* pinned build inputs
* identifiable source revisions
* deterministic configuration
* image metadata
* artifact signing
* reproducibility information
* provenance information

---

## OCI Image Model

CoreOS uses OCI images as a distribution and deployment primitive.

The OCI artifact represents system content, not merely an application container.

The exact mechanism used to transform or deploy OCI content may evolve.

Higher layers must not depend upon the details of that transformation process.

The important platform semantics are:

* the image is identifiable
* the image can be verified
* the image can be deployed transactionally
* the image can be selected for boot
* a previous deployment remains available for rollback

---

## Boot Architecture

The boot process should establish a deterministic path from firmware to a known CoreOS deployment.

Conceptually:

```text
Firmware
   |
   v
Bootloader
   |
   v
Selected CoreOS Deployment
   |
   v
Kernel + initramfs
   |
   v
systemd
   |
   v
Core platform services
   |
   v
Flavor/session environment
```

Boot state must remain inspectable.

Administrators should be able to determine which deployment booted and which deployment is selected for the next boot.

---

## Recovery Architecture

Recovery is a first-class platform capability.

Recovery mechanisms may evolve, but the platform should preserve the ability to:

* inspect deployments
* select a known-good deployment
* diagnose boot failures
* repair machine configuration
* restore platform state where possible
* retrieve useful logs
* recover without modifying immutable system content in place

Recovery must not depend on the broken deployment functioning normally.

---

## Security Architecture

Security should be enforced through architecture rather than conventions.

Core principles include:

* least privilege
* narrow service interfaces
* signed artifacts
* authenticated updates
* explicit trust boundaries
* service isolation
* systemd sandboxing where appropriate
* minimal listening services
* secure defaults
* hardware-backed identity where useful
* encrypted persistent data where appropriate

Security-sensitive operations should have explicit ownership.

Avoid introducing general-purpose privileged mechanisms when a narrower capability is sufficient.

---

## Machine Identity

CoreOS should provide a stable platform identity independent of a particular flavor.

Machine identity may eventually include:

* platform UUID
* deployment identity
* hardware identity
* TPM-backed keys
* enrollment identity
* cryptographic machine credentials

A flavor should consume platform identity through defined interfaces rather than inventing its own machine identity mechanism where possible.

---

## Networking Boundary

CoreOS owns the underlying networking capability required for the machine to function.

This may include:

* interface discovery
* link state
* base network configuration
* DNS plumbing
* routing primitives
* platform network identity
* secure networking policy

Flavors may provide user-facing network workflows and presentation.

CoreOS should expose capabilities without forcing every flavor to understand the implementation details of the networking stack.

---

## Device Boundary

CoreOS owns hardware discovery and privileged device access.

Flavors may consume device capabilities through stable interfaces.

Examples may eventually include:

* graphics devices
* audio devices
* cameras
* removable storage
* radios
* input devices
* Bluetooth
* USB devices
* hardware accelerators

Device policy should distinguish between:

* discovery
* capability reporting
* access authorization
* privileged configuration

---

## Logging and Diagnostics

CoreOS should be observable without being noisy.

Diagnostic information should make it possible to determine:

* what failed
* when it failed
* which deployment was running
* which service was responsible
* whether the failure affects bootability
* whether rollback is available
* whether persistent state may be affected

Logs should use established system facilities where practical.

`corectl diagnostics` should eventually provide a coherent administrative view rather than requiring manual inspection of unrelated subsystems.

---

## Testing Model

CoreOS testing must focus on system behavior, not merely successful compilation.

The repository separates tests into major lifecycle areas:

```text
tests/
├── boot/
├── update/
└── rollback/
```

### Boot Tests

Verify that a produced image:

* boots
* reaches the expected target
* initializes required services
* establishes networking
* exposes platform services

### Update Tests

Verify that a running system can:

* discover a deployment
* retrieve it
* verify it
* stage it
* select it
* boot it successfully

### Rollback Tests

Verify that a machine can return to a previous known-good deployment after:

* administrator request
* failed update
* failed boot
* intentionally introduced regression

Rollback is a core system capability and must be tested as such.

---

## Failure Model

CoreOS assumes components will fail.

Expected failure classes include:

* corrupted downloads
* invalid signatures
* incomplete updates
* unbootable deployments
* service startup failures
* hardware changes
* storage failure
* configuration errors
* network loss
* malformed platform requests
* incompatible flavor behavior

The architecture should prefer failure modes that preserve diagnostic information and recovery options.

A failure should be explicit.

Silent degradation should be avoided where practical.

---

## Service Ownership

Every long-running CoreOS service should have a clearly defined responsibility.

Before adding a daemon, determine:

* what state it owns
* what privilege it requires
* what API it exposes
* which components may call it
* how it starts
* how it fails
* how it is monitored
* how it is tested

A new daemon should not exist merely because separating code into another process is convenient.

Process boundaries should correspond to meaningful architectural, security, or lifecycle boundaries.

---

## Dependency Direction

Dependencies should generally flow downward through stable interfaces.

Conceptually:

```text
Flavor
  |
  v
sessiond / flavor integration
  |
  v
SignalLayer Platform API
  |
  v
sl-platformd
  |
  v
CoreOS base system
  |
  v
kernel / hardware
```

Lower layers must not depend upon flavor-specific behavior.

CoreOS must remain capable of booting and exposing the platform even when no user-facing flavor is functioning correctly.

---

## Architectural Invariants

The following rules should remain true as CoreOS evolves:

1. The running operating system corresponds to an identifiable deployment.
2. Updating creates or activates deployments rather than mutating the running system into an unknown state.
3. A previous known-good deployment remains recoverable during update.
4. Persistent writable state has explicit ownership and purpose.
5. Flavors consume stable platform capabilities instead of implementation details.
6. `sl-platformd` remains the authoritative privileged machine service.
7. `sl-sessiond` remains subordinate to the machine platform boundary.
8. `corectl` remains an administrative client rather than a parallel implementation of platform logic.
9. Applications remain outside CoreOS unless they are required platform components.
10. The system image remains the source of truth for CoreOS system software.
11. CoreOS remains functional independently of any particular flavor.
12. Privileged capabilities are exposed narrowly rather than through arbitrary command execution.
13. Recovery remains possible without relying upon the currently broken deployment.
14. Persistent user and flavor state remain separate from immutable system content.

---

## Repository Mapping

The repository reflects these architectural boundaries:

```text
signallayer-coreos/
├── Containerfile       image definition
├── README.md           project overview
├── docs/               architecture and contracts
├── platformd/          privileged platform authority
├── sessiond/           flavor/session lifecycle
├── corectl/            administrative client
├── config/             CoreOS-owned system policy
├── image/              image construction tooling
├── tests/              lifecycle and system tests
└── flavors/            example/reference flavor integration
```

Directory layout should reflect ownership.

When a component no longer fits clearly within one of these boundaries, that is a signal that the architecture should be reviewed before adding another directory.

---

## Architectural Decision Rule

When introducing a new CoreOS capability, determine:

1. Who owns the capability?
2. Does it require machine-level privilege?
3. Is it CoreOS state, flavor state, or user state?
4. Does the capability belong behind the Platform API?
5. Can the implementation be replaced without affecting flavors?
6. How does the capability fail?
7. How is it recovered?
8. How will it be tested?
9. Does it introduce persistent state?
10. Does it introduce a new trust boundary?

If these questions do not have clear answers, the feature is not architecturally ready.

---

## Summary

SignalLayer CoreOS is responsible for providing a stable, secure, recoverable platform beneath SignalLayer operating-system flavors.

Its architecture intentionally separates:

* machine control from user experience
* immutable system software from persistent state
* privileged operations from unprivileged consumers
* platform capabilities from implementation details
* system lifecycle from application lifecycle

The goal is not to make CoreOS feature-rich.

The goal is to make it trustworthy.
