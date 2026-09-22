# SignalLayer CoreOS — Design Philosophy

**Status:** Draft

**Version:** 0.1

**Project:** SignalLayer CoreOS

> **Document scope:** This is a forward-looking statement of architectural
> principles, not a 0.0.1 capability matrix. See the
> [0.0.1 release notes](releases/0.0.1.md) for implemented and validated
> behavior. Capabilities described with “should” or “must” remain design intent
> unless the release documentation identifies them as implemented.

## Purpose

SignalLayer CoreOS is the minimal, immutable operating-system substrate for
SignalLayer application operating systems such as CloudOS, JumpOS, and future
SignalLayer platforms.

CoreOS is not intended to be a general-purpose desktop distribution.

CoreOS exists to provide a secure, predictable, recoverable, hardware-facing
platform on which higher-level operating environments can run.

The interesting parts belong above CoreOS.

CoreOS should be boring.

## Core principle

> CoreOS should be invisible when it works, obvious when it fails, and trivial
> to recover.

## Design goals

### 1. Minimal

If a component is not required by the platform or substantially all official
SignalLayer OS flavors, it does not belong in CoreOS.

CoreOS should provide:

- kernel and firmware
- hardware support
- boot infrastructure
- networking
- audio and device plumbing
- system services
- update and rollback mechanisms
- security infrastructure
- SignalLayer Platform APIs
- flavor/session infrastructure
- recovery tools

Applications belong to the operating-system flavor, not CoreOS.

### 2. Immutable

The deployed operating system should be treated as an image, not as a mutable
collection of packages.

System software is changed by deploying a new known image.

CoreOS should not encourage or depend upon:

- ad-hoc package installation
- manual modification of system binaries
- configuration drift between machines
- snowflake installations

A deployed machine should always be attributable to a known CoreOS image.

### 3. Secure by default

Security must be architectural rather than optional.

CoreOS should favor:

- minimal attack surface
- least privilege
- signed system artifacts
- verified updates
- service isolation
- sandboxing
- encrypted storage where appropriate
- Secure Boot support
- TPM-backed identity where useful
- no unnecessary listening services
- explicit privilege boundaries

An unused capability should normally be absent rather than merely disabled.

### 4. Recoverable

Failure must be expected.

CoreOS must make recovery simple and deterministic.

A system update must never require blind faith.

CoreOS should support:

- transactional updates
- known-good previous deployments
- rollback
- recovery boot environments
- diagnostic tooling
- reproducible system images

A failed update should be an inconvenience, not an incident.

### 5. Predictable

Identical CoreOS versions should behave identically.

Persistent state must have clearly defined locations and ownership.

CoreOS should avoid hidden state and implicit behavior.

Administrators should be able to determine:

- what version is running
- what image produced it
- whether the system has been modified
- what persistent state exists
- what services are running
- whether an update is available
- what deployment will boot next

without reverse engineering the machine.

### 6. Intuitive

CoreOS may be technically sophisticated internally, but its administrative
interface should be simple.

Routine operations should be obvious.

Examples:

```text
corectl status
corectl update
corectl rollback
corectl reboot
corectl diagnostics
```

Complex implementation details should not leak into routine administration.

### 7. Observable, not noisy

CoreOS should provide excellent diagnostics.

Logs, health information, update status, boot state, and service failures should
be easy to inspect.

However, normal operation should not generate unnecessary noise.

A healthy system should look healthy.

A broken system should clearly explain what is broken.

### 8. Explicit state

CoreOS must distinguish between:

- immutable operating-system content
- machine configuration
- persistent system state
- user state
- caches
- flavor-specific state

Persistent state must never exist merely because a component happened to write
somewhere.

Every persistent location should have an intentional owner and purpose.

### 9. Platform, not personality

CoreOS supplies capabilities.

Application operating systems supply user experience.

CloudOS, JumpOS, and future flavors may have radically different shells,
applications, workflows, and goals while consuming the same CoreOS platform.

CoreOS must not encode assumptions about one particular flavor.

### 10. Stable platform contract

SignalLayer operating-system flavors should depend on the SignalLayer Platform
API rather than CoreOS implementation details.

For example, a flavor should not need to know how CoreOS internally performs:

- system updates
- rollback
- power management
- device discovery
- hardware policy
- platform identity

These capabilities should be exposed through stable interfaces.

This separation allows CoreOS internals to evolve without requiring every
SignalLayer operating system to evolve with them.

### 11. Replaceable internals

CoreOS is the official and supported substrate for SignalLayer operating
systems.

However, the architecture should not unnecessarily bind higher-level operating
systems to a particular Linux distribution or implementation.

CoreOS is the reference implementation of the SignalLayer Platform.

Community projects may implement compatible platform backends on systems such
as Debian, Fedora, Arch Linux, or other environments.

Official SignalLayer OS images will ship on CoreOS.

Alternate substrates are community ports unless explicitly promoted to an
officially supported platform.

### 12. Image reproducibility

The operating-system image is the source of truth.

Given:

- the source tree
- the build definition
- the dependency versions
- the build inputs

it should be possible to reproduce the same operating-system image.

Installation scripts should not determine the final system state.

The image should.

## Non-goals

CoreOS is not intended to be:

- a traditional desktop Linux distribution
- a general-purpose package-management environment
- an application store
- a collection of user applications
- a development workstation
- a server distribution for arbitrary workloads
- a compatibility layer for every Linux convention
- a vehicle for experimentation at the expense of reliability

Those functions may exist in higher-level SignalLayer products.

## Decision test

Before adding something to CoreOS, ask:

- Is this needed by nearly every official SignalLayer OS flavor?
- Does it need privileged or hardware-level access?
- Is placing it here materially more secure or reliable?
- Would implementing it separately in every flavor create unnecessary
  duplication?
- Can CoreOS provide it as a stable platform capability rather than exposing
  implementation details?

If the answer to these questions is mostly no, it probably does not belong in
CoreOS.

## Engineering bias

When choosing between two directions, CoreOS should normally prefer:

| Instead of | Prefer |
| --- | --- |
| clever | understandable |
| feature-rich | minimal |
| flexible | predictable |
| convenient | recoverable |
| new | proven |

Innovation belongs where it creates user value.

Infrastructure should earn trust through consistency.

## Success

CoreOS is successful when users of CloudOS, JumpOS, and other SignalLayer
operating systems rarely need to think about CoreOS at all.

Administrators should trust that it will:

- boot
- connect
- authenticate
- expose the expected platform
- update safely
- recover reliably

and otherwise stay out of the way.
