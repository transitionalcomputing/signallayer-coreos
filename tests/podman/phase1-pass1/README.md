# Phase 1 Pass 1 experiment

This directory contains the bounded v0.0.4 rootless system-service bootstrap
experiment. `fixture.c` produces a non-product OCI fixture. `guest-probe.sh`
provisions the disposable guest and performs the two-boot runtime and authority
tests. `run-qcow2.py` boots an overlay with genuine KVM and preserves evidence.
It evaluates strict, complete evidence only after QEMU exits. Missing, malformed,
duplicate, truncated, or failed required records make the run fail. Every
maintained assertion has an offline negative control in `test_harness.py`.
An empty structured AVC query is valid only when `journalctl` returns its exact
`-- No entries --` result; retrieval errors and malformed JSON fail. The guest
also records the authoritative rootless API path's metadata, kernel Unix-socket
table entry, same-identity API connection result, and container-root view on
both boots without enabling or reconfiguring the socket.

Re-evaluate a preserved completed run without booting a VM:

```bash
python3 run-qcow2.py --evaluate-report /path/to/report.json
```

The experiment requires a qcow2 built from the exact pinned base and a read-only
ext4 fixture disk containing `fixture.oci.tar`, `fixture.ref`, and
`provenance.txt`. It never writes the source qcow2 or fixture disk.

This is a disposable feasibility experiment. It does not install Podman,
identities, systemd units, policy, storage, or networking into CoreOS.
