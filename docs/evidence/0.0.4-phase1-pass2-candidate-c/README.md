# Candidate C feasibility evidence

Status: **28/28 PASS — DISPOSABLE FEASIBILITY EXPERIMENT ONLY**

This package preserves the successful genuine-KVM run authorized by GitHub
issue #36. Fedora 44 Podman 5.8.7 launched a fixed executable with rootless
`run --rootfs` from a root-owned, `container_file_t`, read-only bind mount.
The fixed system service ran as locked `sl-management`; the container had
private namespaces, no capabilities, no new privileges, seccomp mode 2, no
network, and no Podman API socket. A missing-rootfs launch failed without
damaging the native multi-user system, and the fixed service then restarted.

The source qcow2 and fixture disk were attached read-only and had unchanged
checksums after QEMU exited. SELinux remained Enforcing, no related AVC was
observed, and QEMU powered down cleanly.

The result establishes only the feasibility of the recorded disposable
`--rootfs` mechanism. Production rootfs construction and packaging, trusted
reset and verification, continuous spawn exclusion, dedicated SELinux policy,
private rootless networking, and A-to-B-to-A lifecycle remain **UNPROVEN**.

Package contents:

- `report.json`: completed machine report and input identities.
- `evaluation.json`: strict 28-assertion result.
- `guest-evidence.tsv`: raw structured guest evidence.
- `serial.log`: complete serial transcript.
- `PROVENANCE.md`: source, host, firmware, and artifact identities.
- `REDACTIONS.md`: exact publication-only sanitization and original hashes.
- `REPRODUCE.md`: offline verification and replay commands.
- `SHA256SUMS`: evidence-file hashes.

The unredacted originals remain in the restricted development-host evidence
directory identified by the private execution record. `report.json` and
`serial.log` are sanitized publication derivatives; the structured evidence
and evaluation are unchanged.
