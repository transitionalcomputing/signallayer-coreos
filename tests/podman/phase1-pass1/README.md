# Phase 1 Pass 1 experiment

This directory contains the bounded v0.0.4 rootless system-service bootstrap
experiment. `fixture.c` produces a non-product OCI fixture. `guest-probe.sh`
provisions the disposable guest and performs the two-boot runtime and authority
tests. `run-qcow2.py` boots an overlay with genuine KVM and preserves evidence.

The experiment requires a qcow2 built from the exact pinned base and a read-only
ext4 fixture disk containing `fixture.oci.tar`, `fixture.ref`, and
`provenance.txt`. It never writes the source qcow2 or fixture disk.
