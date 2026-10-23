# Candidate C evidence provenance

## Source

- Repository: `transitionalcomputing/signallayer-coreos`
- Base: `d1c5368e7aedc8e5cb0fbeaf53f865050e594ce9`
- Original local execution commit: `4e5f3ecba89dcaa6205aa3b86995d50ac81ba5ee`
- Published source-equivalent commit: `ac22edc8b1a8bbc223495426d3e316c0f69f5449`
- Run date: 2026-10-23

Prepublication history was rewritten for privacy and to remove generated
bytecode. The executable experiment files in the published commit are
byte-for-byte identical to the files used for the run:

| File | SHA-256 |
| --- | --- |
| `guest-probe.sh` | `872eef7e7fde2a68132826faac28c75388489d3b67a8013d00d8c0adce0c7777` |
| `run-qcow2.py` | `348932f9596672d5d27bd1ffa7ed7f1591534d5593b358ffb3eaa91d65bc2d66` |
| `test_harness.py` | `fbd5dd1dff24c202dc0a6b411cdb8bb6e5d4d6e9609602ef011411772ff1ed73` |

## Host and firmware

- Host: authorized Fedora 44 development host, native x86_64
- Acceleration: KVM (`q35,accel=kvm`, `-cpu host`)
- QEMU: 10.2.2 (`qemu-10.2.2-1.fc44`)
- OVMF: `edk2-ovmf-20260812-8.fc44`
- `OVMF_CODE.fd`: `904bfa3e0d966372b43b804c4fe323ae63751566687c2bfdf52ca947f47eb13a`
- template `OVMF_VARS.fd`: `6ed987af3a3c155be71665f510eae3e007eda9b8b94afd59d45e91c4a11565cc`

## Immutable inputs

| Input | SHA-256 |
| --- | --- |
| Base qcow2 | `60a0eeef6d8f1063f99979cf576bb4a2992a0a1530cba33b2d9b1ef660560cef` |
| Fixture ext4 disk | `73d26643bcdb3dc9902d4cd292e19b68d067e16aa984ebecc2dd930193ab2491` |
| Fixture OCI archive | `b821320317e12471d649ed5a33a068219c45bc7349840a4e978f6f4c8bdd35d1` |

The base qcow2 reports origin `localhost/sl-phase1-base:pass1` and manifest
`sha256:be66d07ce8114567d275a4c92b71a6eb0efb60023f73cfc33727e99355a0b5cb`.
Both disks were attached read-only. All guest changes were confined to the
disposable qcow2 overlay, which is retained only in the original host run.

`evaluation.json` and `guest-evidence.tsv` are byte-for-byte copies.
`report.json` and `serial.log` are publication derivatives with only the
host/path/identifier substitutions documented in `REDACTIONS.md`. The strict
evaluator still reproduces 28/28 from these files. `SHA256SUMS` hashes the
published package.
