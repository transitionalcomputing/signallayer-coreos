# SignalLayerIT CoreOS — Flavor Contract

**Status:** Draft
**Version:** 0.1
**Project:** SignalLayerIT CoreOS

## Purpose

The SignalLayer Flavor Contract defines the supported relationship between
SignalLayerIT CoreOS and higher-level SignalLayer operating-system flavors.

A flavor provides the application environment and user experience.

CoreOS provides the machine platform beneath it.

The contract exists so that flavors can evolve independently of CoreOS while
remaining compatible with the SignalLayer Platform.

---

## Core Principle

> CoreOS owns the machine. Flavors own the experience.

A flavor should describe and consume the capabilities it needs.

It should not take ownership of the underlying machine.

---

## Examples of Flavors

SignalLayer operating-system flavors may include:

* CloudOS
* JumpOS
* future graphical environments
* remote-access environments
* specialized workstation environments
* appliance-style environments

Different flavors may provide radically different user experiences while
consuming the same CoreOS platform.

---

# Responsibilities

## CoreOS Responsibilities

CoreOS is responsible for platform capabilities that are broadly required
across SignalLayer operating systems.

These include:

* kernel and firmware
* hardware support
* boot infrastructure
* system initialization
* base networking
* device discovery
* security infrastructure
* deployment lifecycle
* system updates
* rollback
* recovery
* machine identity
* privileged platform services
* persistent platform-state boundaries
* SignalLayer Platform APIs
* flavor and session infrastructure

---

## Flavor Responsibilities

A flavor is responsible for the user-facing operating environment.

This may include:

* graphical shell
* desktop environment
* application launcher
* applications
* remote desktop environment
* user workflows
* application policy
* product-specific services
* visual design
* branding
* flavor-specific configuration
* flavor-specific persistent data

Applications belong to flavors unless they provide a capability required by
nearly every supported SignalLayer environment.

---

# Flavor Independence

CoreOS must not depend upon the behavior of one specific flavor.

CoreOS should remain capable of:

* booting
* establishing networking
* starting platform services
* reporting platform health
* updating
* rolling back
* entering recovery

even when the installed or active flavor is broken.

A failed flavor should not imply a failed CoreOS deployment.

---

# Platform Independence

A flavor should not depend upon undocumented CoreOS implementation details.

A flavor should consume the SignalLayer Platform API wherever a platform
capability exists.

The flavor should generally not care:

* which Linux distribution forms the CoreOS base
* how OCI images become bootable deployments
* which bootloader is used
* how deployment metadata is stored
* which Linux utility performs a platform action
* how hardware enumeration is internally implemented
* where private CoreOS implementation files are stored

---

# Supported Dependency Boundary

Conceptually:

```text
SignalLayer Flavor
        |
        v
Flavor Runtime / sl-sessiond
        |
        v
SignalLayer Platform API
        |
        v
sl-platformd
        |
        v
CoreOS
        |
        v
Kernel / Hardware
```

Dependencies should flow downward through defined interfaces.

CoreOS must not acquire dependencies on individual flavor implementations.

---

# Flavor Structure

A flavor should have an identifiable root describing its integration with the
SignalLayer platform.

A conceptual flavor may contain:

```text
example-flavor/
├── flavor.toml
├── services/
├── sessions/
├── config/
├── assets/
└── state/
```

The precise on-disk format is not finalized.

The contract defined here is semantic rather than tied to one manifest syntax.

---

# Flavor Identity

Every flavor must have a stable identifier.

For example:

```text
com.signallayer.cloudos
com.signallayer.jumpos
```

A flavor identity should not change merely because its display name changes.

Flavor metadata should eventually include:

* stable flavor ID
* display name
* flavor version
* required Platform API version
* required capabilities
* optional capabilities
* session entry point
* state requirements

---

# Flavor Manifest

A flavor should declare its requirements rather than assuming them.

Conceptually:

```text
id = "com.signallayer.cloudos"
name = "CloudOS"
version = "0.1.0"

platform_api = ">=0.1"

requires = [
    "networking",
    "devices",
    "power"
]

optional = [
    "tpm",
    "secure-boot"
]
```

This is illustrative only.

The final manifest format will be specified separately when implementation
begins.

---

# Capability Requirements

A flavor may declare required platform capabilities.

If a required capability is unavailable, the platform should fail activation
clearly rather than allowing unpredictable partial operation.

Optional capabilities may change behavior without preventing activation.

For example:

```text
required:
    networking
    graphics

optional:
    bluetooth
    camera
    tpm
```

A flavor must not assume that optional capabilities exist.

---

# Platform API Compatibility

A flavor must declare the Platform API version or compatibility range it
requires.

CoreOS should verify compatibility before activating the flavor.

A flavor requiring an unsupported platform contract should fail with an
explicit compatibility error.

Compatibility failure is preferable to undefined behavior.

---

# Flavor Lifecycle

The flavor lifecycle should be explicit.

Conceptually:

```text
discovered
    |
    v
validated
    |
    v
prepared
    |
    v
active
    |
    v
stopping
    |
    v
inactive
```

Failure may occur during validation, preparation, startup, operation, or
shutdown.

The platform should report the lifecycle state clearly.

---

# Flavor Discovery

CoreOS or `sl-sessiond` must be able to discover installed flavors through a
defined mechanism.

Discovery should identify:

* flavor ID
* flavor version
* manifest
* compatibility requirements
* session entry points

Discovery must not depend upon arbitrary filesystem scanning conventions that
are undocumented.

---

# Flavor Validation

Before activation, the platform should validate:

* manifest syntax
* flavor identity
* platform API compatibility
* required capabilities
* declared entry points
* required persistent-state locations
* security policy where applicable

A flavor that fails validation must not enter an active session.

---

# Flavor Activation

Flavor activation should prepare the environment necessary for the flavor to
run.

Activation may include:

* validating platform requirements
* preparing flavor state
* mounting or exposing flavor resources
* creating runtime directories
* preparing devices
* starting flavor services
* creating a user session

Activation should not mutate immutable CoreOS system content.

---

# Flavor Deactivation

Deactivation should provide an orderly path for stopping a flavor.

The platform should allow the flavor reasonable opportunity to:

* terminate sessions
* flush persistent state
* stop flavor services
* release devices
* release temporary resources

A malfunctioning flavor must not be able to prevent machine-level recovery or
administration indefinitely.

---

# Session Model

A flavor may create one or more sessions.

A session represents an active user-facing environment.

Session responsibilities may include:

* user environment setup
* graphical or shell startup
* application environment
* runtime variables
* flavor-specific services
* user authentication integration

`sl-sessiond` coordinates session lifecycle.

---

# `sl-sessiond`

`sl-sessiond` is the CoreOS component responsible for flavor and session
lifecycle coordination.

It should provide:

* flavor discovery
* flavor validation
* activation
* deactivation
* session startup
* session teardown
* session health reporting
* controlled access to required platform capabilities

It should not become a second privileged machine-management service.

Machine-level operations should continue to flow through `sl-platformd`.

---

# Privilege Model

A flavor must operate with the minimum privilege required.

Flavor processes should not receive unrestricted root access merely because
they form part of an operating environment.

Privileged operations should normally occur through the Platform API.

For example, a flavor wanting to reboot the machine should request:

```text
system.reboot
```

rather than executing arbitrary privileged commands.

---

# Forbidden Assumptions

A flavor must not assume that it may:

* write to immutable CoreOS system paths
* replace CoreOS binaries
* replace CoreOS platform services
* change the bootloader directly
* manipulate deployment metadata directly
* install arbitrary packages into CoreOS
* modify CoreOS systemd units in place
* bypass `sl-platformd` for privileged operations
* depend upon private CoreOS filesystem paths
* depend upon internal update-engine behavior

If a legitimate platform requirement cannot be satisfied through the existing
contract, the contract should be extended deliberately.

---

# Filesystem Model

A flavor must distinguish between:

* flavor image content
* flavor configuration
* flavor persistent state
* user state
* runtime state
* cache

Flavor data must not be stored inside immutable CoreOS system content.

---

# Flavor Content

Flavor-owned immutable content may include:

* applications
* graphical shell
* libraries
* flavor-specific services
* assets
* default configuration
* templates

The mechanism used to distribute flavor content may evolve.

The contract should not unnecessarily bind flavors to one packaging mechanism.

---

# Flavor Configuration

Configuration specific to a flavor should belong to that flavor.

Examples may include:

* default UI preferences
* application policy
* remote-session settings
* flavor feature flags
* product-specific configuration

Machine-level platform configuration belongs to CoreOS.

---

# Flavor Persistent State

Persistent flavor state belongs to the flavor rather than the CoreOS image.

Examples may include:

* service databases
* flavor policy state
* application metadata
* session metadata that must survive reboot

Every persistent location should have an identifiable owner and lifecycle.

---

# User State

User data must remain logically distinct from both:

* immutable CoreOS system content
* immutable flavor content

A CoreOS update or flavor update should not destroy user state.

---

# Runtime State

Temporary session state should be considered disposable unless explicitly
documented otherwise.

Examples may include:

* sockets
* PID files
* transient IPC state
* temporary session files

Runtime state should not become an accidental persistence mechanism.

---

# Cache

Flavor caches should be reconstructable.

Deleting cache data must not destroy meaningful user or platform state.

---

# Update Independence

CoreOS updates and flavor updates are conceptually separate lifecycles.

Updating CoreOS should not require rebuilding a flavor unless the platform
contract changes incompatibly.

Updating a flavor should not require mutating CoreOS system content.

The architecture should allow:

```text
CoreOS version A + Flavor version X

CoreOS version B + Flavor version X

CoreOS version B + Flavor version Y
```

where declared compatibility permits.

---

# CoreOS Update Behavior

Before activating a new CoreOS deployment, the platform should be able to
determine whether installed flavors remain compatible with the target Platform
API.

Compatibility checks should eventually occur before reboot where practical.

A CoreOS update should not silently strand the machine with no compatible
flavor when this can be detected beforehand.

---

# Flavor Update Behavior

Flavor updates should preserve:

* user state
* declared flavor state
* platform compatibility
* recovery paths where applicable

Flavor updates should not modify CoreOS deployment metadata.

---

# Failure Isolation

A flavor failure should remain distinguishable from a CoreOS failure.

Examples include:

```text
CoreOS healthy / flavor healthy
CoreOS healthy / flavor failed
CoreOS degraded / flavor unknown
CoreOS recovery / flavor inactive
```

Diagnostic tooling should preserve this distinction.

---

# Flavor Crash

If the active flavor crashes, CoreOS should remain administratively accessible.

Where practical, `sl-sessiond` may:

* record failure
* stop remaining flavor services
* attempt controlled restart
* expose diagnostics
* fall back to a recovery environment

Restart policy should avoid infinite crash loops.

---

# Flavor Boot Failure

Failure to start a flavor does not automatically make the CoreOS deployment
invalid.

The system should distinguish between:

* platform boot success
* platform service health
* flavor activation success

This distinction is important for rollback policy.

---

# Recovery Environment

Recovery must not depend upon the normal flavor functioning.

A recovery environment may be implemented as:

* a minimal built-in environment
* a dedicated recovery flavor
* another platform-controlled interface

Whatever the implementation, recovery authority remains owned by CoreOS.

---

# Hardware Access

A flavor should consume hardware through normal unprivileged interfaces or
Platform API capabilities.

Direct hardware access may be appropriate for some classes of device, but the
ownership and authorization model must remain explicit.

A flavor should not automatically receive access to every discovered device.

---

# Device Requirements

A flavor may declare hardware or capability requirements.

For example:

```text
requires:
    graphics
    input.keyboard

optional:
    camera
    bluetooth
    gpu.compute
```

A capability requirement is preferable to requiring a particular vendor,
driver, or Linux device name when the flavor does not truly depend upon those
implementation details.

---

# Networking

CoreOS owns the underlying networking substrate.

A flavor may provide:

* network configuration UI
* connection workflows
* network status presentation
* application-level networking policy

Privileged machine network changes should occur through supported platform
interfaces.

A flavor should not silently replace CoreOS networking infrastructure.

---

# Power Management

A flavor may expose user-facing actions such as:

* reboot
* shutdown
* suspend
* restart into another environment

The actual machine operation should be requested through the Platform API.

This keeps authorization and machine-state transitions under platform control.

---

# Authentication

CoreOS may provide authentication primitives or platform identity.

A flavor may provide the user-facing authentication experience.

The exact division will depend on the authentication architecture.

Flavor authentication must not require storing secret machine credentials in
flavor-controlled locations without explicit platform design.

---

# Logging

Flavor logs should remain distinguishable from CoreOS platform logs.

Diagnostic tooling should be able to identify:

* platform logs
* session-manager logs
* flavor-service logs
* application logs

A flavor should not overwrite or suppress CoreOS diagnostic information.

---

# Health Reporting

A flavor should expose enough health information for `sl-sessiond` to determine
whether the environment is operating normally.

Conceptually, flavor health might include:

```text
starting
healthy
degraded
failed
stopping
inactive
```

Health semantics should be defined before automated remediation depends on them.

---

# Flavor Diagnostics

A flavor may contribute diagnostic information to a platform diagnostic bundle.

Any such integration must define:

* what data is collected
* size limits
* sensitivity
* secret filtering
* failure behavior

A broken flavor must not prevent CoreOS diagnostics from completing.

---

# Security

Flavors are not inherently trusted merely because they are installed.

The platform should eventually support controls such as:

* manifest validation
* artifact verification
* service sandboxing
* explicit capabilities
* device access policy
* filesystem boundaries
* resource controls
* authenticated flavor updates

The exact security model will evolve with implementation.

---

# Resource Isolation

CoreOS may enforce resource limits on flavors.

Potential resources include:

* CPU
* memory
* storage
* device access
* process count
* network capability

Resource policy must distinguish intentional platform protection from arbitrary
restrictions on valid flavor functionality.

---

# Flavor Artifacts

Official flavors should eventually be attributable to identifiable artifacts.

Useful metadata may include:

* flavor version
* image or artifact digest
* build revision
* build provenance
* signature state

Flavor deployment should aim for the same predictability principles used by
CoreOS.

---

# Official and Community Flavors

The platform may distinguish between:

* official SignalLayer flavors
* third-party compatible flavors
* experimental flavors

Compatibility does not necessarily imply official support.

Official status may carry additional requirements involving:

* testing
* signing
* update policy
* security review
* lifecycle support

---

# Compatibility

A compatible flavor must:

1. provide a stable flavor identity
2. declare its Platform API requirements
3. declare required platform capabilities
4. keep its mutable state outside immutable CoreOS content
5. use supported platform interfaces for privileged operations
6. avoid dependencies on private CoreOS implementation details
7. provide valid lifecycle entry points
8. tolerate absence of optional capabilities
9. fail clearly when required capabilities are unavailable
10. preserve the CoreOS privilege boundary

---

# Flavor Contract Versioning

The flavor contract itself must be versioned.

A future manifest may declare something conceptually similar to:

```text
flavor_contract = "1"
platform_api = ">=0.1"
```

The flavor-contract version describes packaging and lifecycle expectations.

The Platform API version describes machine capabilities.

These are related but distinct compatibility dimensions.

---

# Example Flavor

The repository contains:

```text
flavors/example/
```

This directory should eventually contain a minimal reference implementation
demonstrating the supported integration model.

The example flavor should:

* declare identity
* declare platform requirements
* start successfully
* expose a basic session
* consume at least one Platform API capability
* maintain clearly owned state
* stop cleanly
* demonstrate failure reporting

The example flavor should remain intentionally simple.

Its purpose is to document the contract through working code.

---

# Flavor Test Requirements

A flavor integration test should eventually verify:

* manifest parsing
* compatibility detection
* capability checking
* activation
* session startup
* Platform API access
* deactivation
* failure handling
* persistence boundaries

Official flavors should additionally be tested against supported CoreOS
versions.

---

# CoreOS Test Requirements

CoreOS should test the flavor boundary independently of production flavors.

The example flavor can provide a stable test target.

CoreOS tests should verify that:

* a valid flavor starts
* an incompatible flavor is rejected
* missing required capabilities are reported
* a failed flavor does not take down platform services
* flavor state survives appropriate lifecycle events
* immutable CoreOS content cannot be mutated through normal flavor interfaces

---

# Contract Evolution

The flavor contract should evolve conservatively.

New optional capabilities may be introduced without breaking existing flavors.

Breaking lifecycle or packaging changes should require explicit contract-version
changes.

A change to internal CoreOS implementation does not justify changing the flavor
contract unless externally visible semantics actually change.

---

# Design Rule

Before adding something to the flavor contract, ask:

1. Is this genuinely required for interoperability?
2. Does it describe a stable semantic boundary?
3. Is this a flavor responsibility or a CoreOS responsibility?
4. Does it expose an implementation detail unnecessarily?
5. What privilege does it require?
6. What persistent state does it create?
7. What happens when it fails?
8. Can existing flavors continue to operate?
9. Can an alternate platform implementation honor the same contract?
10. Does this belong in the Platform API instead?

If responsibility is unclear, the contract should not be expanded yet.

---

# Architectural Invariants

The following should remain true:

1. CoreOS remains operational independently of a specific flavor.
2. Flavors own user experience rather than machine authority.
3. Flavors use stable platform capabilities for privileged machine operations.
4. Flavor state remains separate from immutable CoreOS content.
5. User state remains separate from both CoreOS and flavor images.
6. CoreOS and flavor update lifecycles remain independently manageable.
7. A flavor crash does not inherently invalidate a CoreOS deployment.
8. Recovery does not depend upon the active flavor functioning.
9. Optional platform capabilities remain discoverable rather than assumed.
10. Flavors depend on semantic capabilities rather than private implementation
    details.

---

# Summary

The SignalLayer Flavor Contract creates a boundary between the machine platform
and the operating environment presented to the user.

CoreOS provides:

* hardware
* security
* lifecycle
* recovery
* privileged capabilities
* stable platform interfaces

A flavor provides:

* applications
* workflows
* presentation
* user environment
* product-specific behavior

The contract exists so that both sides can evolve without becoming entangled.

CoreOS should not become the flavor.

The flavor should not become CoreOS.
