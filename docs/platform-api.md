# SignalLayerIT CoreOS — Platform API

**Status:** Draft
**Version:** 0.1
**Project:** SignalLayerIT CoreOS

## Purpose

The SignalLayer Platform API defines the stable interface between the CoreOS
platform and higher-level SignalLayer operating-system components.

The API exists so that flavors such as CloudOS, JumpOS, and future SignalLayer
systems can request platform capabilities without depending upon CoreOS
implementation details.

The Platform API defines **what the platform can do**.

It does not require callers to understand **how CoreOS does it**.

---

## Core Principle

> Flavors consume capabilities, not implementation details.

A caller should request an operation such as:

```text
Get platform status
Check for update
Stage update
Reboot
Roll back
List devices
Query machine identity
```

It should not need to know:

* how deployments are stored
* which bootloader is installed
* how OCI images are materialized
* which filesystem layout CoreOS uses internally
* which Linux utilities implement an operation
* which files contain internal platform metadata

---

## Scope

The Platform API is intended to expose machine-level capabilities including:

* platform identity
* CoreOS version and deployment state
* system health
* update lifecycle
* rollback
* reboot and shutdown
* hardware discovery
* device capabilities
* networking state
* recovery state
* diagnostic information

Additional capability groups may be introduced as CoreOS evolves.

---

## Non-Goals

The Platform API is not intended to provide:

* arbitrary root command execution
* unrestricted filesystem access
* arbitrary systemd unit manipulation
* direct bootloader manipulation
* direct access to internal deployment metadata
* general-purpose package management
* application installation
* flavor-specific UI behavior
* unrestricted kernel or device configuration

If a flavor needs a privileged capability, CoreOS should expose the narrowest
reasonable operation rather than a generic privileged escape hatch.

---

## Authority

`sl-platformd` is the authoritative implementation of privileged Platform API
operations in SignalLayerIT CoreOS.

Clients may include:

* `corectl`
* `sl-sessiond`
* trusted flavor services
* recovery tooling
* administrative interfaces

Clients should not duplicate platform business logic.

---

## API Stability

The Platform API is intended to become a stable contract.

Internal CoreOS implementation may change without requiring compatible clients
to change.

For example, CoreOS may change:

* deployment technology
* update transport
* bootloader
* Linux distribution base
* internal storage layout
* hardware discovery implementation

without changing the semantics of:

```text
platform.status
update.check
update.stage
deployment.rollback
system.reboot
device.list
```

when the existing contract can still be honored.

---

## Versioning

The Platform API must expose a protocol version.

Conceptually:

```text
Platform API: 0.1
```

API version information should allow clients to determine:

* protocol version
* supported capability groups
* optional capabilities
* deprecated capabilities

The platform should prefer additive evolution over breaking changes.

---

## Capability Discovery

Clients must not assume every compatible SignalLayer Platform implementation
supports every optional capability.

The platform should expose capability discovery.

Conceptually:

```text
platform.capabilities
```

A result may eventually describe capabilities such as:

```text
updates
rollback
power
devices
networking
tpm
secure-boot
recovery
diagnostics
```

Capability discovery is especially important for alternate community platform
implementations.

---

# API Model

The API is organized into logical capability namespaces.

Initial namespaces are:

```text
platform.*
deployment.*
update.*
system.*
device.*
network.*
diagnostics.*
recovery.*
```

These names describe semantic groupings.

They do not prescribe the final transport mechanism.

---

# Platform Operations

## `platform.status`

Return the high-level state of the machine.

This should provide enough information for an administrator or flavor to
determine whether the platform is functioning normally.

Conceptual response:

```text
state: healthy
coreos_version: 0.0.1
platform_api_version: 0.1
deployment: <deployment-id>
booted: true
update_state: idle
rollback_available: true
```

The exact serialized representation is not yet defined.

---

## `platform.version`

Return platform version information.

Expected information includes:

* CoreOS version
* Platform API version
* build identifier
* image identifier
* source revision where available

---

## `platform.identity`

Return stable machine-level identity information.

Possible fields may include:

* platform UUID
* machine identifier
* hardware identifier where appropriate
* enrollment identity
* TPM-backed identity availability

Sensitive key material must never be returned through this operation.

---

## `platform.capabilities`

Return capabilities supported by the current platform implementation.

This permits clients to adapt to:

* older CoreOS releases
* hardware differences
* alternate SignalLayer Platform implementations
* optional subsystems

---

# Deployment Operations

## `deployment.current`

Return the currently booted deployment.

Expected information may include:

* deployment ID
* CoreOS version
* image reference
* image digest
* creation time
* boot status
* verification status

---

## `deployment.next`

Return the deployment selected for the next boot.

If no deployment switch is pending, this may refer to the current deployment.

---

## `deployment.list`

Return known deployments.

Conceptually:

```text
current
next
previous-known-good
other-retained-deployments
```

The implementation may retain more than two deployments, but callers must not
depend upon a particular storage mechanism.

---

## `deployment.rollback`

Select a previous known-good deployment.

This operation should:

1. validate that a rollback target exists
2. ensure the target remains bootable according to available metadata
3. select the target for the next boot
4. report whether reboot is required

Rollback selection should not silently reboot unless the API operation
explicitly requests that behavior.

---

## `deployment.accept`

Mark the currently running deployment as successfully accepted where the
deployment lifecycle requires such a state.

This may be used after successful startup or health validation.

The exact acceptance policy remains an implementation decision.

---

# Update Operations

The update API separates discovery, retrieval, staging, activation, and reboot.

This separation is intentional.

An update request should not automatically imply an immediate reboot.

---

## `update.status`

Return current update state.

Possible states may include:

```text
idle
checking
available
downloading
verifying
staging
staged
failed
```

Additional states may be defined later.

---

## `update.check`

Check the configured update source for an available deployment.

Expected result may include:

* update available
* target version
* image reference
* image digest
* release metadata
* restart requirement

Checking must not modify the active deployment.

---

## `update.download`

Retrieve the selected update artifact.

Downloading an update must not activate it.

Downloaded content must be verified before it can become a bootable deployment.

---

## `update.stage`

Prepare a verified image as a new deployment.

Staging must preserve the current known-good deployment.

A successfully staged deployment should become inspectable through the
deployment API.

---

## `update.activate`

Select a staged deployment for the next boot.

Activation must not imply that the deployment has already been proven healthy.

---

## `update.cancel`

Cancel an update operation where cancellation remains safe.

Cancellation semantics depend upon update state.

For example, cancellation may be possible while downloading but not while
committing critical boot metadata.

The API must report when cancellation is unavailable.

---

# System Power Operations

Power operations require privileged authority.

They must remain narrow and explicit.

---

## `system.reboot`

Request a system reboot.

The API should allow the caller to receive confirmation that the reboot request
was accepted.

Future versions may support metadata such as:

```text
reason
requested_by
delay
```

---

## `system.shutdown`

Request an orderly system shutdown.

---

## `system.reboot_to_deployment`

Request reboot into a specific valid retained deployment.

This operation must only accept deployments already known and validated by the
platform.

It must not accept arbitrary filesystem paths, kernel arguments, or bootloader
commands.

---

# Device Operations

The device API exposes hardware capability without requiring callers to inspect
Linux internals directly.

---

## `device.list`

Return devices known to the platform.

Device classes may eventually include:

* graphics
* audio
* input
* camera
* storage
* networking
* Bluetooth
* USB
* radio
* accelerator
* security hardware

---

## `device.get`

Return information about a specific platform device.

Possible information may include:

* stable platform device ID
* device class
* manufacturer
* model
* capabilities
* current availability
* driver state
* access policy

---

## `device.capabilities`

Return the capabilities associated with a device.

A flavor should generally ask whether a capability exists rather than depend
upon a specific Linux driver name.

---

# Networking Operations

CoreOS owns the base networking substrate.

The Platform API should expose useful state without forcing flavors to parse
Linux networking internals.

---

## `network.status`

Return high-level networking state.

Possible information includes:

* connectivity
* active interfaces
* addresses
* default route availability
* DNS availability

---

## `network.interfaces`

Return platform network interfaces and their capabilities.

The interface presented by the API should not require the caller to understand
the exact network management backend.

---

## Configuration Operations

Network configuration APIs are intentionally not fully defined yet.

Network configuration introduces policy questions involving:

* machine configuration
* flavor UX
* administrative authority
* persistence
* remote management safety

These semantics should be designed before exposing mutating network operations.

---

# Diagnostics Operations

## `diagnostics.summary`

Return a concise health summary.

This is the logical source for information used by:

```text
corectl diagnostics
```

Expected categories may include:

* deployment
* update service
* platform services
* networking
* storage
* hardware
* boot state

---

## `diagnostics.services`

Return health information for CoreOS-owned platform services.

This should expose platform semantics rather than becoming a generic wrapper
around `systemctl`.

---

## `diagnostics.logs`

Provide controlled access to relevant CoreOS diagnostic logs.

This API must consider:

* sensitive information
* log size
* authorization
* filtering
* retention

It should not expose arbitrary filesystem reads.

---

## `diagnostics.bundle`

Generate a bounded diagnostic bundle suitable for troubleshooting.

The bundle should document what information it includes.

Sensitive machine credentials and secret key material must never be included.

---

# Recovery Operations

Recovery capabilities must remain accessible independently of the user-facing
flavor wherever practical.

---

## `recovery.status`

Return information about the system's recovery state.

Possible information includes:

* rollback availability
* retained deployments
* last boot result
* current deployment health
* recovery environment availability

---

## `recovery.rollback`

Request recovery to a known-good deployment.

This operation may share implementation with `deployment.rollback`, but the
recovery namespace exists to allow recovery-specific policy and tooling.

---

## `recovery.diagnostics`

Return diagnostics specifically useful when normal platform startup has failed.

---

# Error Model

The API must return structured errors.

Clients must not be expected to interpret arbitrary human-readable strings to
determine failure semantics.

Conceptual error classes include:

```text
InvalidRequest
Unauthorized
Forbidden
NotSupported
NotFound
Busy
Conflict
VerificationFailed
DeploymentInvalid
UpdateUnavailable
NetworkUnavailable
InsufficientStorage
HardwareUnavailable
InternalError
```

Human-readable descriptions may accompany structured error identifiers.

---

## Error Requirements

Errors should communicate:

* what operation failed
* the structured failure class
* whether retry may succeed
* whether machine state changed
* whether recovery action is required

A failed mutating operation must not leave callers uncertain about whether the
requested state transition occurred.

---

# Authorization Model

Not every client should have access to every Platform API operation.

At minimum, the design must distinguish between:

* read-only inspection
* routine session operations
* administrative operations
* destructive or recovery operations

Examples:

```text
platform.status          read-only
device.list              read-only
update.check             limited mutation
update.stage             administrative
deployment.rollback      administrative
system.reboot            privileged
diagnostics.bundle       controlled
```

The precise authorization mechanism will be defined with the transport.

---

# Idempotency

Where practical, platform operations should be idempotent.

Examples:

Requesting:

```text
update.check
```

multiple times should not alter machine state unnecessarily.

Selecting an already-selected deployment should not create additional
deployments.

Operations that cannot be idempotent must clearly document their behavior.

---

# Long-Running Operations

Some platform operations may take significant time.

Examples include:

* downloading an update
* verifying an image
* staging a deployment
* generating diagnostics

The API should eventually support operation tracking rather than requiring a
client connection to remain open indefinitely.

Conceptually:

```text
operation_id: <id>
state: running
progress: 42
```

A later request could inspect:

```text
operation.status(<id>)
```

The operation model is not yet finalized.

---

# Events

Some platform changes are better represented as events than by polling.

Possible events include:

```text
platform.health.changed
update.available
update.progress
update.failed
deployment.changed
device.added
device.removed
network.changed
shutdown.requested
```

The transport mechanism for events remains undecided.

---

# Transport

The Platform API transport is intentionally unspecified in version 0.1 of this
document.

Potential mechanisms include:

* D-Bus
* Unix domain sockets
* another local IPC mechanism

Transport selection must consider:

* privilege separation
* authentication
* authorization
* reliability
* language interoperability
* introspection
* implementation complexity
* sandbox compatibility

Network exposure is not assumed.

The initial Platform API should be local to the machine unless a strong
architectural reason requires otherwise.

---

# Security Requirements

The Platform API must:

* validate all inputs
* authenticate privileged callers where necessary
* authorize individual capabilities
* avoid shell command interpolation
* avoid arbitrary filesystem paths where possible
* use stable object identifiers
* prevent privilege escalation through parameter manipulation
* expose the minimum required information
* log security-relevant state changes
* avoid returning secret material

Transport convenience must not weaken the privilege boundary.

---

# Compatibility Requirements

A compatible SignalLayer Platform implementation should:

1. expose a Platform API version
2. expose capability discovery
3. implement required operations for its declared compatibility level
4. preserve documented operation semantics
5. return structured errors
6. avoid requiring flavors to know implementation-specific details

Alternate implementations need not reproduce CoreOS internals.

They need to reproduce the contract.

---

# Required Initial API Surface

For the early CoreOS development milestone, the minimum useful Platform API is:

```text
platform.status
platform.version
platform.capabilities

deployment.current
deployment.list
deployment.rollback

update.status
update.check
update.stage

system.reboot

diagnostics.summary
```

This surface is intentionally small.

Additional capabilities should be added when real platform requirements justify
them.

---

# Relationship to `corectl`

`corectl` should primarily map administrative commands onto Platform API
operations.

Conceptually:

```text
corectl status
    -> platform.status

corectl update
    -> update.check
    -> update.stage

corectl rollback
    -> deployment.rollback

corectl reboot
    -> system.reboot

corectl diagnostics
    -> diagnostics.summary
```

The CLI may provide presentation, confirmation, and workflow orchestration.

It should not independently implement deployment or hardware logic.

---

# Relationship to `sl-sessiond`

`sl-sessiond` may consume Platform API capabilities necessary to establish and
manage a flavor session.

It should receive only the authority required for that role.

Session management must not imply unrestricted machine administration.

---

# Relationship to Flavors

Flavors should treat the Platform API as their supported boundary to CoreOS.

A flavor should not normally:

* manipulate CoreOS deployment files
* modify bootloader state
* invoke internal update utilities directly
* parse private CoreOS metadata
* alter CoreOS system services
* depend on undocumented filesystem paths

When a legitimate platform capability is missing, the preferred solution is to
extend the Platform API deliberately.

---

# Design Rule

Before adding an API operation, ask:

1. Is this a platform capability rather than a flavor feature?
2. Who should be authorized to call it?
3. Does it require privilege?
4. What state does it mutate?
5. Is that state persistent?
6. Is the operation recoverable?
7. Can it be made idempotent?
8. How does it report partial failure?
9. Can the implementation change without changing the semantic contract?
10. Is the operation narrower than exposing the underlying implementation?

If these questions do not have clear answers, the API operation is not ready.

---

# Summary

The SignalLayer Platform API exists to create a durable boundary between
SignalLayer operating-system flavors and the CoreOS substrate.

Its purpose is not to expose every CoreOS function.

Its purpose is to expose the smallest stable set of platform capabilities
necessary for higher-level operating systems to use the machine safely.

CoreOS implementations may change.

The platform contract should remain understandable, predictable, and stable.
