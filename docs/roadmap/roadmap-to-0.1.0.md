# SignalLayer OS roadmap to 0.1.0

**Document status:** PROVISIONAL

**Planning range:** SignalLayer CoreOS 0.0.3 through SignalLayer OS 0.1.0

**Baseline:** `v0.0.3`, validated source
`a286544a670fb62f3b834217a7c4478a45cc1945`

**Last reviewed:** 2026-10-18

## Purpose and interpretation

This document sequences the architectural work needed to turn the validated
CoreOS foundation into the first cohesive SignalLayer OS platform foundation.
It is a planning document, not an implementation claim, release promise or
substitute for a milestone-specific design and acceptance contract.

Statements in this roadmap use four evidence classes:

- **Verified capability** means behavior demonstrated by retained acceptance
  evidence for a published release.
- **Approved direction** means an architectural constraint approved for future
  designs, but not necessarily implemented.
- **Proposed detail** means a plausible implementation approach that remains
  subject to review and may be replaced without changing the roadmap goal.
- **Unresolved decision** means work that must be decided explicitly before the
  affected implementation begins.

The roadmap preserves the boundaries in
[architecture.md](../architecture.md),
[flavor-contract.md](../flavor-contract.md),
[platform-api.md](../platform-api.md), and
[architecture-direction.md](../architecture-direction.md). Where those draft
documents describe future surfaces, this roadmap does not promote them to
implemented status.

## Architectural vision

SignalLayer OS is built in layers with authority flowing downward through
constrained interfaces:

```text
Management UI and future product roles
                  |
                  v
Containerized Management Plane
  desired state / reconciliation / workload policy
                  |
                  v
Authenticated and authorized platform interfaces
                  |
                  v
SignalLayer CoreOS
  bootstrap / recovery / machine authority / Podman foundation
                  |
                  v
Linux / systemd / SELinux / hardware
```

CoreOS remains the minimal, immutable, product-neutral machine substrate.
`sl-platformd` remains the authority for privileged machine operations. The
Management Plane runs above that boundary in a Podman container, owns desired
state and reconciliation, and receives only explicitly delegated capabilities.
It does not become root merely because it orchestrates workloads.

Podman is the required workload execution runtime on the path to 0.1.0. It is
also placed behind a runtime-adapter boundary so that Podman-specific mechanics
do not become the durable Management Plane contract. VM or microVM backends may
be added later behind an appropriate boundary; they are not required for 0.1.0.

The Management UI is a separate managed workload. It consumes Management Plane
interfaces and may be replaced without replacing the Management Plane or
CoreOS. CoreOS must bootstrap and recover the Management Plane when the UI is
absent, and must remain bootable, diagnosable, updatable and recoverable when
the Management Plane or Podman is broken.

## Current validated platform baseline

SignalLayer CoreOS 0.0.3 is **released and closed**. Its verified baseline is
recorded in the [milestone closure](../milestones/0.0.3-closure.md) and
[release notes](../releases/0.0.3.md).

Verified capabilities include:

- a bootable x86_64 bootc/OCI system image and qcow2 under genuine KVM with
  OVMF UEFI;
- an immutable, read-only root and `/usr`, with persistent state separate from
  image-owned system content;
- systemd and NetworkManager health, enforcing SELinux and confined platform
  services;
- Platform API 0.3, status schema 0.3 and Session1 status schema 0.4;
- fixed, root-authorized update, reboot and rollback operations with no
  caller-controlled command or systemd unit;
- update staging, explicit activation, retained-deployment rollback and exact
  A -> B -> A lifecycle restoration;
- a trusted local appliance console, local authentication and recovery flows;
- authenticated, LAN-only, read-only remote status with fail-closed listener
  invalidation; and
- Phase 5E acceptance at 75/75 and full A -> B -> A lifecycle acceptance at
  45/45.

These capabilities are inputs to later milestones. Later work integrates with
the existing deployment lifecycle and does not reimplement bootc update,
staging, explicit activation or rollback.

## Major architectural invariants

The following constraints apply across every milestone:

1. CoreOS remains minimal, immutable and authoritative over machine-level
   operations.
2. `sl-platformd` remains the sole privileged machine-mutation authority;
   clients receive narrow capabilities rather than arbitrary commands, paths or
   systemd units.
3. Podman is the foundational workload runtime through 0.1.0, behind a durable
   runtime-adapter boundary.
4. The Management Plane runs in a Podman container and is not part of the
   immutable CoreOS process namespace merely for convenience.
5. CoreOS bootstraps, monitors and recovers the Management Plane without
   depending on the Management Plane to perform those actions.
6. The Management UI is separate from the Management Plane and has no implied
   machine authority.
7. Declarative desired state governs workloads and managed platform components;
   observed state remains distinguishable from desired state.
8. Management requests cross authenticated, authorized and narrowly scoped
   platform interfaces.
9. Rootless execution and SELinux confinement are the defaults. Exceptions
   require a documented capability, threat analysis and acceptance evidence.
10. Persistent platform, management, workload and user state remain separate
    from immutable CoreOS deployments and have explicit ownership and
    lifecycle.
11. CoreOS remains bootable and administratively recoverable when Podman, the
    Management Plane, the Management UI or any workload is absent or failed.
12. CoreOS and workload lifecycles remain independently manageable. A workload
    failure does not inherently invalidate a CoreOS deployment.
13. Product roles and user-facing environments depend on semantic platform
    capabilities, not private CoreOS, Podman or bootc implementation details.
14. Reference workloads validate platform behavior without becoming premature
    CloudOS, ServerOS, JumpOS or other product-role implementations.

## Release sequence

| Release | Theme | Status |
| --- | --- | --- |
| 0.0.3 | CoreOS Foundation | Released and closed |
| 0.0.4 | Podman Foundation | Planned |
| 0.0.5 | Management Plane | Planned |
| 0.0.6 | Workload Management | Planned |
| 0.0.7 | Resource Management | Planned |
| 0.0.8 | Installation System | Planned |
| 0.0.9 | Platform Integration | Planned |
| 0.1.0 | Platform Foundation Developer Preview | Planned |

Version numbers define dependency order, not calendar commitments. Each planned
release requires its own reviewed contract, threat model, evidence plan and
release authorization.

## Milestone dependencies

```text
0.0.3 CoreOS Foundation
   |
   v
0.0.4 Podman Foundation
   |
   v
0.0.5 Management Plane
   |
   v
0.0.6 Workload Management
   |
   v
0.0.7 Resource Management
   |
   v
0.0.8 Installation System
   |
   v
0.0.9 Platform Integration
   |
   v
0.1.0 Platform Foundation Developer Preview
```

Later milestones may design ahead, but they must not bypass the accepted
contracts or evidence gates of their prerequisites.

## 0.0.3 — CoreOS Foundation

**Status:** RELEASED AND CLOSED

### Objective

Establish the immutable machine substrate, constrained local management
boundary and validated deployment lifecycle on which the roadmap depends.

### Evidence

The published release, artifact identities, limitations and acceptance results
are authoritative in the
[0.0.3 closure record](../milestones/0.0.3-closure.md). No work in later
milestones changes the meaning of that evidence.

## 0.0.4 — Podman Foundation

**Status:** PLANNED

### Objective

Provide secure, recoverable rootless container execution as a CoreOS platform
capability suitable for bootstrapping the future Management Plane and running
bounded reference workloads.

### Expected deliverables

- a pinned Podman runtime integrated into the immutable CoreOS image;
- a versioned runtime-adapter contract that hides replaceable Podman mechanics
  from higher layers;
- deterministic bootstrapping of rootless containers under dedicated service
  identities;
- explicit persistent, runtime and cache storage ownership;
- SELinux policy, systemd lifecycle and resource-boundary foundations for
  rootless containers;
- image identity, provenance and admission requirements for bootstrapped
  components;
- a CoreOS-owned recovery path that can diagnose, disable, reset or restore the
  container bootstrap path without a functioning Management Plane; and
- minimal non-product reference containers used only to validate execution,
  restart, isolation, persistence and recovery.

### High-level acceptance criteria

- a rootless reference container starts after boot without granting it root,
  ambient capabilities, host filesystem authority or broad device access;
- its immutable image identity and mutable storage ownership are observable;
- SELinux and systemd prevent mutation of CoreOS content and unauthorized
  cross-container access;
- restart, host reboot, runtime failure and corrupted/invalid image cases fail
  predictably and preserve CoreOS administrative recovery;
- CoreOS remains healthy when Podman or the reference container is stopped or
  broken; and
- existing 0.0.3 update, rollback, console and immutable-root behavior remains
  intact.

### Proposed implementation details

Systemd-managed rootless Podman/Quadlet units, dedicated system users and
explicit state directories are candidates, not frozen requirements. The design
must select mechanisms only after confirming their Fedora/Podman lifecycle and
SELinux semantics.

### Unresolved decisions

- runtime-adapter wire/API shape and ownership;
- rootless identity allocation and subordinate-ID policy;
- image transport, trust, signature and local-cache policy;
- persistent storage layout, backup semantics and reset behavior; and
- the minimal privileged assistance, if any, required for networking, storage
  or bootstrap.

## 0.0.5 — Management Plane

**Status:** PLANNED

### Objective

Run a product-neutral Management Plane in a rootless Podman container. It owns
declarative desired state and reconciliation while CoreOS retains machine
authority, bootstrap and recovery.

### Expected deliverables

- an identifiable, versioned Management Plane container artifact;
- CoreOS-owned bootstrap, health observation and bounded recovery that does not
  depend on the Management Plane itself;
- a declarative configuration model with distinct desired, observed and error
  state;
- a deterministic reconciliation loop with idempotent operations and explicit
  failure/backoff semantics;
- authenticated and authorized interfaces between Management Plane, runtime
  adapter and Platform API;
- durable state ownership, migration, backup and recovery rules outside the
  immutable CoreOS deployment; and
- management APIs that expose state and narrowly scoped intent without
  arbitrary command, filesystem or systemd access.

### High-level acceptance criteria

- CoreOS boots and exposes recovery when the Management Plane image, state or
  process is missing, corrupt or crash-looping;
- the Management Plane runs rootless and confined, with no implicit access to
  the host Podman socket, CoreOS internals or privileged Platform methods;
- authorized declarative changes converge or report structured failure without
  losing the last known desired state;
- restarts and host reboots preserve durable state and resume reconciliation;
- stale or unauthenticated clients cannot mutate desired state; and
- the Management UI is absent from the trusted Management Plane core and can be
  replaced independently.

### Proposed implementation details

A local authenticated API, schema-versioned declarative documents and an
adapter-mediated runtime connection are candidate designs. The Management
Plane's language, database and exact API transport are not selected here.

### Unresolved decisions

- configuration schema, merge/ownership rules and transaction model;
- service identity, credential issuance, rotation and revocation;
- API transport and authorization model across the container boundary;
- reconciliation journal/database choice and migration strategy;
- bootstrap image selection and safe upgrade/rollback of the Management Plane;
  and
- whether `sl-sessiond` code is reused, replaced or remains a separate service.

## 0.0.6 — Workload Management

**Status:** PLANNED

### Objective

Manage declarative container workloads through the Management Plane, including
lifecycle, persistent storage, networking, health and isolation, without
turning workloads into machine authorities.

### Expected deliverables

- a versioned workload specification with identity, artifact, configuration,
  lifecycle, storage, network, health and dependency declarations;
- create/update/stop/remove and observed-state reconciliation through the
  runtime adapter;
- explicit persistent-volume ownership and lifecycle independent of immutable
  images;
- bounded workload networking and service exposure;
- dependency ordering, restart/backoff and failure-isolation behavior;
- workload logs, events and diagnostics with secret redaction; and
- small reference workloads that validate the contract without implementing a
  SignalLayer product role.

### High-level acceptance criteria

- desired workload state converges idempotently after process, Management Plane
  and host restarts;
- invalid or unauthorized specifications fail without partial privilege or
  leaked resources;
- workload replacement preserves declared persistent state and does not mutate
  CoreOS or other workload state;
- network exposure and inter-workload communication match explicit policy;
- a failed workload does not take down CoreOS, the Management Plane or unrelated
  workloads; and
- workload artifact and runtime identities remain observable for diagnosis and
  provenance.

### Unresolved decisions

- workload schema and compatibility/versioning rules;
- network backend and service-discovery model;
- volume drivers, encryption, backup and portability semantics;
- secrets delivery and in-memory/on-disk handling;
- orchestration dependency semantics and health model; and
- boundary between generic workload, platform component, role and subrole.

## 0.0.7 — Resource Management

**Status:** PLANNED

### Objective

Discover, authorize, allocate and account for CPU, memory, GPU, storage and
device resources through explicit platform policy.

### Expected deliverables

- normalized resource and device inventory with stable semantic identifiers;
- declarative requests, limits, reservations and allocation state;
- authorization policy for device and accelerator access;
- enforcement through appropriate cgroup, SELinux, device and runtime controls;
- contention, exhaustion and revocation behavior; and
- resource telemetry sufficient for reconciliation and diagnosis without
  exposing unrestricted host internals.

### High-level acceptance criteria

- allocations cannot exceed authorized or available capacity;
- workloads cannot acquire undeclared devices or escape CPU, memory, process,
  storage or device limits;
- conflicting requests produce deterministic structured results;
- reboot and workload restart preserve or safely reconstruct allocation state;
- device disappearance and resource exhaustion fail safely; and
- CoreOS retains resources required for machine control and recovery.

### Unresolved decisions

- stable device identity across replacement/reboot;
- GPU partitioning and vendor-neutral capability representation;
- overcommit, reservation, priority and preemption policy;
- storage quota/accounting mechanisms; and
- which policy is enforced by CoreOS, the runtime adapter or the Management
  Plane without duplicating authority.

## 0.0.8 — Installation System

**Status:** PLANNED

### Objective

Provide a modular, verifiable installation and initial-configuration system for
CoreOS and supported SignalLayer platform components while preserving the
immutable deployment and explicit-state model.

### Expected deliverables

- installation media or workflow with attributable CoreOS artifacts;
- modular selection/configuration of supported platform components without
  arbitrary package mutation of the running deployment;
- storage layout, persistent-state and recovery partitioning rules;
- machine identity, enrollment and initial credential/configuration flow;
- preflight hardware/capability checks and clear unsupported-system results;
- repeatable, resumable or safely restartable installation behavior; and
- post-install verification and a path into CoreOS-owned recovery.

### High-level acceptance criteria

- a blank supported target becomes a bootable, identifiable CoreOS deployment
  with the selected platform components;
- installation failure does not silently produce an ambiguous or partially
  trusted system;
- installed immutable content matches verified source artifacts;
- persistent state and secrets are created with explicit ownership and secure
  permissions;
- reinstall, repair and recovery behavior is documented and tested; and
- installation does not depend on the installed Management Plane being healthy.

### Unresolved decisions

- installation media, UX and unattended configuration format;
- partitioning, encryption, TPM and recovery-key policy;
- artifact signature/trust-root and offline installation model;
- component-selection granularity and compatibility checks; and
- upgrade/migration behavior for machines originating from Developer Preview
  artifacts.

## 0.0.9 — Platform Integration

**Status:** PLANNED

### Objective

Harden and validate the complete platform across security, reliability,
compatibility, recovery, installation and lifecycle boundaries before the
0.1.0 Developer Preview.

### Expected deliverables

- a supported configuration and compatibility matrix;
- integrated threat-model review and narrowed privilege inventory;
- end-to-end install, bootstrap, management, workload, resource, CoreOS update
  and recovery suites;
- failure-injection coverage for network loss, storage pressure, invalid
  artifacts, crash loops, stale state and interrupted operations;
- upgrade/migration and compatibility policy for every persistent schema;
- operator diagnostics, evidence retention and release-readiness procedures;
  and
- resolution or explicit acceptance of security and reliability gaps carried
  from issue #19 and preceding milestone reviews.

### High-level acceptance criteria

- a fresh supported machine can install, bootstrap the Management Plane and run
  a reference workload without undocumented manual repair;
- CoreOS update/rollback does not destroy Management Plane or workload state;
- Management Plane and workload failure leave CoreOS recovery available;
- authentication, authorization, SELinux, rootless isolation and secret
  handling pass positive and negative tests;
- recovery is demonstrated for representative failures at each layer;
- no unresolved release blocker remains; and
- every release artifact is attributable, integrity-checked and accompanied by
  retained machine-readable evidence.

### Unresolved decisions

- exact supported hardware/configuration matrix;
- release signing and trust distribution requirements;
- severity thresholds and waiver process for 0.1.0;
- performance, scale and soak-test targets; and
- which deferred hardening items are mandatory for 0.1.0 versus explicitly
  documented Developer Preview limitations.

## 0.1.0 — Platform Foundation Developer Preview

**Status:** PLANNED

### Objective

Publish a cohesive, secure, installable and manageable operating-system
foundation on which future SignalLayer product roles can be built without
weakening CoreOS machine authority or binding the platform to one user-facing
environment.

### Expected deliverables

- attributable installation and runtime artifacts with checksums, provenance
  and release documentation;
- immutable CoreOS with independently recoverable Podman and Management Plane
  bootstrap;
- declarative Management Plane and workload APIs with explicit compatibility
  versions;
- rootless, SELinux-confined workload execution with persistent storage,
  networking and resource policy;
- local recovery and diagnostics that work without workloads or Management
  Plane availability;
- documented supported configurations, security boundary, known limitations
  and upgrade/rollback behavior; and
- complete retained acceptance evidence for the published artifacts.

### Definition of success

0.1.0 succeeds when a supported target can be installed from verified
artifacts, boot into healthy immutable CoreOS, independently bootstrap a
confined Management Plane, accept authorized declarative configuration, run and
recover isolated reference workloads with explicit persistent state and
resource policy, survive CoreOS and component lifecycle operations, and retain
CoreOS-owned diagnosis and recovery when every higher layer is unavailable.

The Developer Preview must demonstrate this behavior end to end with published
artifact identities and repeatable evidence. It need not ship CloudOS,
ServerOS, JumpOS or another product role.

## Cross-milestone security requirements

Every planned milestone must:

- document its trust boundaries, principals, credentials, persistent state and
  privileged operations before implementation;
- prefer rootless processes, capability-free service identities and enforcing
  SELinux domains;
- grant narrowly typed filesystem, D-Bus, socket, device and systemd access;
- reject arbitrary command execution, arbitrary unit control and caller-chosen
  privileged paths or backend arguments;
- authenticate identities and authorize individual operations rather than
  treating network or container location as trust;
- verify workload and platform artifact identity before activation;
- keep secrets out of logs, status surfaces, images and declarative documents
  not designed to carry them;
- fail closed when an authoritative source, owner or policy disappears;
- bound requests and long-running operations with observable state and
  structured failure; and
- preserve a CoreOS-owned recovery path below Podman and the Management Plane.

Security exceptions require an explicit design record, the smallest defensible
scope, negative tests and release-level acceptance. Convenience is not a
justification for broad host authority.

## Explicit exclusions through 0.1.0

The roadmap does not authorize:

- CloudOS, ServerOS, JumpOS or any specialized product-role implementation;
- a product-specific shell, desktop, remote workspace or user experience;
- Kubernetes as a required platform dependency;
- VM or microVM workload execution as a 0.1.0 requirement;
- arbitrary host command execution, package installation into immutable CoreOS
  or generic systemd control from the Management Plane;
- moving bootc deployment authority out of CoreOS;
- automatic CoreOS reboot or automatic health-triggered rollback without a
  separate approved contract;
- a Management UI embedded into the trusted Management Plane core; or
- treating minimal reference workloads as shipped SignalLayer products.

## Deferred capabilities

The following are deliberately deferred until after 0.1.0 unless a reviewed
milestone contract promotes a narrowly required prerequisite:

- CloudOS, ServerOS, JumpOS and specialized operating roles;
- production product-role catalogs, marketplaces or fleet orchestration;
- Kubernetes and alternate runtime backends;
- general VM and microVM lifecycle management;
- multi-tenant product policy beyond the isolation required to validate the
  platform foundation; and
- product-specific application, desktop, shell and workflow layers.

Items already tracked in
[issue #19](https://github.com/transitionalcomputing/signallayer-coreos/issues/19)
remain unresolved until a milestone-specific review accepts or implements
them. This roadmap does not close that issue.

## Architectural consistency and unresolved decisions

Existing documents use both **flavor** and the newer directional term
**role**. The approved direction says roles may contain multiple instances and
subroles, but the existing flavor contract remains in force until deliberately
replaced. This roadmap uses neutral terms such as workload and product role and
does not silently revise the flavor contract.

The forward-looking `docs/platform-api.md` remains a draft version 0.1 design
document, while the validated local D-Bus implementation has advanced to
Platform API 0.3. A future documentation decision must reconcile the conceptual
API taxonomy with the released wire contract before new Management Plane
methods are standardized.

Other unresolved cross-cutting decisions include:

- the exact CoreOS-to-runtime-adapter and Management-Plane-to-adapter contracts;
- trust roots, artifact signing, credential lifecycle and attestation;
- declarative schema ownership, versioning, transaction and migration rules;
- state layout, backup, encryption and disaster-recovery policy;
- networking, ingress, service discovery and firewall enforcement;
- division of policy between CoreOS, Management Plane and runtime without
  creating competing authorities; and
- the formal compatibility relationship among platform API, workload contract,
  role/flavor contract and installation manifests.

These are required design gates, not permission to block all preparatory work.
The affected milestone must resolve them before implementation makes the choice
expensive or externally visible.

## Roadmap revision policy

This roadmap is provisional and may change through normal review. Revisions
must:

1. use a focused documentation pull request;
2. identify which statements are verified capability, approved direction,
   proposed detail or unresolved decision;
3. cite the contract or acceptance evidence affected by the change;
4. preserve published release history and never rewrite prior evidence;
5. explain milestone dependency, security-boundary and compatibility effects;
6. avoid representing planned capability as implemented;
7. update milestone-specific contracts before implementation when authority,
   persistent state or public interfaces change; and
8. receive explicit release authorization before tags, artifacts or published
   status change.

Moving an objective between provisional releases does not by itself approve an
implementation. Material changes to CoreOS authority, Management Plane trust,
runtime isolation, persistence or recovery require a dedicated architectural
decision and acceptance plan.
