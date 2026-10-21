# Evidence provenance

## Source

- Repository: `transitionalcomputing/signallayer-coreos`
- Base experiment merged on `main`:
  `cbe14888d1576a42da9f4ba86e5020c809bffec9`
- Final diagnostic harness and accepted source:
  `93e949e229acf25207d4b7d95dcc9d1de3f05676`
- Final run date: 2026-10-21

## Host and firmware

- Host: `slit-coreosdev-01`, native x86_64
- Acceleration: genuine KVM (`/dev/kvm`)
- QEMU: 10.2.2 (`qemu-10.2.2-1.fc44`)
- Firmware package: `edk2-ovmf-20260812-8.fc44`

## Immutable inputs

| Input | SHA-256 |
| --- | --- |
| Base qcow2 | `60a0eeef6d8f1063f99979cf576bb4a2992a0a1530cba33b2d9b1ef660560cef` |
| Fixture ext4 disk | `73d26643bcdb3dc9902d4cd292e19b68d067e16aa984ebecc2dd930193ab2491` |
| Fixture OCI archive | `b821320317e12471d649ed5a33a068219c45bc7349840a4e978f6f4c8bdd35d1` |

The source qcow2 and fixture disk were attached read-only. Guest mutations
were confined to a disposable qcow2 overlay.

The base qcow2 contains exported OCI config ID
`sha256:d312275bca51c0a0e28a30b5fe75d8027f540a21713934b84a35f77174e3ef7b`
and exported manifest
`sha256:be66d07ce8114567d275a4c92b71a6eb0efb60023f73cfc33727e99355a0b5cb`.
The fixture records config ID
`sha256:ed114162e2c3c7863b03f237057877308a8a3970628c1a940fc1e94080aa070c`
and manifest
`sha256:f790c07e851f17634492ef5a17f27be42d4454684275df606ef2376f1d44da99`.

## Original evidence

The authoritative host directory is:

```text
/home/coreos/sl-phase1-pass1-16e1e6a/run/phase1-pass1-final-93e949e/
```

The committed `report.json`, `evaluation.json`, `guest-evidence.tsv`, and
`serial.log` are byte-for-byte copies. Their hashes are recorded in
`SHA256SUMS`. No redactions were needed.
