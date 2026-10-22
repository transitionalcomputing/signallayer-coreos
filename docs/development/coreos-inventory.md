# CoreOS source inventory safeguard

Status: adopted engineering safeguard.

`tools/coreos-inventory` compares the current source-declared CoreOS surface
with the accepted baseline in `config/coreos-source-inventory.json`, and checks
the exact build contract in `config/coreos-build-contract.json`. The inventory
baseline was generated from `main` at
`d1860e8ffa6a385beb3632ecdfc40e916eeaaf67` and then explicitly marked
accepted for this safeguard change. Ordinary checks and build entry points
never update it.

## Covered source declarations

The deterministic JSON inventory records:

- the final Containerfile base reference and explicitly installed runtime
  packages;
- installed native systemd unit files, their content hashes, and enable/mask
  symlink operations;
- installed system D-Bus policy/service files and parsed allow/deny rules,
  including machine-detectable method exposure;
- installed sysusers files and identity declarations;
- Cargo workspace package names, paths, and package versions;
- every maintained SELinux policy input and its hash; and
- CoreOS-owned `/usr/bin` and `/usr/libexec/signallayer` entry points declared
  by Containerfile copies.

The tool reports additions, removals, and changed values in human-readable
form. `--format json` returns the same result for automation. Any difference
exits nonzero and names the changed surface.

Within this documented source grammar, missing or changed declarations and
instructions fail closed. That statement does not extend to installed or
transitive artifact contents.

The Containerfile parser recognizes only the project's uppercase instruction
grammar and constructs logical instructions before stage boundaries. The build
contract records every complete instruction in every stage, the ordered and
pinned `FROM` graph, every exact `COPY --from` provenance edge, and hashes of
maintained build-context inputs. A changed, added, or removed runtime `RUN`
therefore differs as a complete instruction; shell pipelines, substitutions,
redirections, variables, globs, or extra commands cannot inherit approval from
an accepted prefix. Unknown/external stages, alias collisions, malformed
continuations, unsupported casing, and unknown instructions fail explicitly.
The checker is deliberately not a general shell or Dockerfile parser.

These are **source-declared** checks. They do not prove compiler output and
cannot enumerate transitive RPM
packages inherited from the pinned base or resolved by DNF, generated units,
loaded SELinux policy, or the final installed artifact without building and
inspecting an image. Those installed-artifact properties remain **UNPROVEN**
by this task and must not be inferred from a passing source comparison.

## Routine use

```bash
tools/coreos-inventory --root .
tools/coreos-inventory --root . --format json
```

The OCI preflight stage, `tools/build-release-oci`, and
`image/build/build-qcow2.sh` run the comparison before expensive work.

## Controlled baseline update

An authorized inventory change uses this sequence:

1. Generate an unapproved candidate outside the baseline path:

   ```bash
   tools/coreos-inventory --root . \
     --candidate-output /tmp/coreos-source-inventory.candidate.json
   ```

2. Compare the candidate with the accepted baseline and review every package,
   unit, D-Bus method/rule, identity, Cargo component, SELinux input and
   executable change, including its security and recovery consequences.
3. Obtain product-owner approval for consequential CoreOS surface changes as
   required by `ENGINEERING.md`.
4. In the authorized change only, set `approval_status` to `accepted`, record
   the reviewed source commit as `accepted_source`, and replace the baseline.
5. Preserve the inventory diff and approval rationale in the PR evidence, then
   rerun the comparison and negative controls.

The tool refuses to write to the accepted baseline path, refuses to overwrite
an existing candidate, and rejects any baseline not explicitly marked
`accepted`. Generating a candidate does not approve it.

An authorized Containerfile or copied-input change similarly generates a
review candidate outside the committed contract:

```bash
tools/coreos-inventory --root . \
  --contract-candidate-output /tmp/coreos-build-contract.candidate.json
```

Review the complete instruction, COPY provenance, and input-hash diff before
replacing the committed contract. The product owner is the approval authority;
the committed JSON files are evidence of that decision, not independent
authorization. Repository writers can modify those files, so branch review
remains part of the control.

## Independent release intent

Release-bound OCI builds use:

```bash
tools/build-release-oci <planned-os-version> \
  --tag <image-reference> \
  --evidence image/build/output/release-oci-evidence.json
```

The wrapper requires a clean Git tree, owns the absolute repository context,
`Containerfile`, release arguments, source revision, deterministic build ID,
and tag. It inspects the immutable output ID and required labels after Podman
exits, checks that the tag still resolves to that ID, and only then writes a
versioned JSON record containing source, immutable ID, available manifest
identity, labels, builder version, and invocation identity. Arbitrary Podman
options and positional contexts are unsupported.

Release-bound disk builds use:

```bash
image/build/build-qcow2.sh --release-intent <planned-os-version> \
  --release-evidence image/build/output/release-oci-evidence.json \
  [local CoreOS OCI reference]
```

The disk gate requires the same clean source commit and compares the selected
local image's immutable ID and labels with that record before creating an
output directory. Mutable tags and self-declared public labels are insufficient
on their own. Direct developer builds keep their established command and do not
produce release evidence.

This developer-preview provenance model trusts the local build host and the
record stored on it. An administrator who can replace both the image and record
can forge the pair; no signing key or external transparency or attestation
service is introduced here. Installed-artifact inventory and transitive payload
proof remain **UNPROVEN** and require post-build inspection and runtime
acceptance. Human product-owner approval remains separate from every executable
check.
