# SignalLayer CoreOS: architecture direction

**Status:** Direction, not a frozen contract. It records where the
architecture is heading so that near-term decisions do not close off that path.
It changes no frozen document and no released or 0.0.3 behavior. Each point
becomes binding only through its own reviewed design.

## CoreOS stays the product-neutral substrate

- CoreOS is the bootable, updatable, recoverable machine. It knows nothing
  about SignalLayer products or what a machine is for.
- sl-platformd remains the sole machine-mutation authority. Its methods stay
  fixed and product-neutral: machine state, updates, rollback, reboot and
  remote-management lifecycle. It does not learn product or role concepts.

## A Management Plane above CoreOS

- A Management Plane above CoreOS owns desired state and reconciles observed
  state toward it.
- **Role supersedes "flavor"** as the unit of purpose. A role has:
  - a **type** (what kind of workload it is);
  - **instances**, plural from day one (a machine can run several instances
    of a role type, and a role type is never assumed to be a singleton);
  - **subroles** (a role instance may be composed of smaller roles);
  - **desired and observed state**, kept distinct, with reconciliation
    between them.
- There is no mass rename yet. Existing documents that say "flavor",
  including [flavor-contract.md](flavor-contract.md), stay as they are until
  the role workstream replaces them deliberately.

## Runtime backends behind an adapter boundary

- Podman is a runtime backend behind an adapter boundary. The Management
  Plane talks to the adapter, not to Podman directly.
- Kubernetes is an optional future backend behind the same boundary, never a
  dependency of CoreOS or of the Management Plane.

## The UI is a replaceable managed workload

- The UI is a replaceable workload that the Management Plane manages, not part
  of the substrate.
- **In 0.0.3,** sl-remoted serves the bundled web UI. This is a transitional
  packaging choice, not an architectural commitment.
- **In the role architecture,** the remote API endpoint (TLS, authentication,
  the fixed API surface) stays platform infrastructure, and the UI becomes a
  workload served through it or beside it.

## Recovery stays below the role infrastructure

- CoreOS must stay bootable and administrable, and its recovery paths must
  keep working, when the Management Plane, Podman, any role or the UI is
  broken or absent.
- Recovery (the local console, the boot-time reset, rollback) therefore lives
  below the role infrastructure and must never depend on it.

## Privilege is capability-delegated

- Privilege is delegated as explicit, bounded capabilities. It is not
  inherited from orchestration responsibility: being responsible for running
  workloads does not make a component root, or make it the machine authority.
- **The first design gate** of the role workstream is privilege delegation
  between the Management Plane, the runtime engine and Platform: which
  capabilities each holds, how they are granted and bounded, and how Platform
  remains the sole machine authority.

## sl-sessiond as a seed

- sl-sessiond is the conceptual seed of the Management Plane's lifecycle side:
  today it aggregates machine state for its callers without owning it.
- This is no commitment that the Management Plane is a single daemon, or that
  it grows out of sl-sessiond's code.
