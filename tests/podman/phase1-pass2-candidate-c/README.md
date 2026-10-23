# Phase 1 Pass 2 Candidate C feasibility experiment

This directory contains the disposable experiment authorized by GitHub issue
#36. It tests Fedora 44 Podman 5.8.7 rootless `run --rootfs` against a fixed,
root-owned rootfs exposed through a read-only bind mount. It does not install
Podman, an identity, a service, policy, or the proposed reset/verifier design
into the CoreOS image.

The source qcow2 and existing fixture disk are attached read-only. The guest
uses the existing verified fixture OCI archive only to materialize an exploded
rootfs inside its disposable overlay. Root owns and labels that tree, then
bind-mounts it read-only before the rootless launch. This proves neither a
production deployment-rootfs construction path nor trusted reset.

Run the focused offline checks:

```bash
python3 test_harness.py
python3 -m py_compile run-qcow2.py test_harness.py
bash -n guest-probe.sh
```

On an authorized Fedora 44 x86_64 KVM host, run:

```bash
python3 run-qcow2.py \
  <verified-base.qcow2> \
  <verified-fixture.ext4> \
  --output <output-directory> \
  --timeout 900
```

The runner verifies both immutable input hashes before boot and again after
QEMU exits. It evaluates strict structured evidence only after shutdown.
Missing, malformed, duplicate or failed required records fail acceptance. The
negative case uses a missing rootfs and proves native networking and the
multi-user system remain active before the fixed service is restarted
successfully.

Re-evaluate preserved evidence without QEMU:

```bash
python3 run-qcow2.py --evaluate-report /path/to/report.json
```

Release-Identity: none

CoreOS-Surface-Change: none (disposable experiment only)
