# CoreOS source inventory safeguard

Status: adopted engineering safeguard.

`tools/coreos-inventory` compares the current source-declared CoreOS surface
with the accepted baseline in `config/coreos-source-inventory.json`. The
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

The runtime-stage parser is deliberately narrow and fail closed. It accepts
the reviewed package-install command, single-source shell-form `COPY`
instructions to known inventory destinations, the existing release/policy
setup commands, and systemd activation forms represented in the inventory.
`ADD`, alternate package-manager syntax, package removal, JSON or multi-source
`COPY`, unknown destinations, unrecognized mutation commands, and direct or
shell-generated writes to protected systemd, D-Bus, sysusers, SELinux and
CoreOS executable locations are errors. New syntax requires an explicit parser
and negative-control update before it can enter an accepted build. The few
reviewed runtime `COPY` exceptions outside the ordinary inventory destinations
are bound to their exact source/stage and, for maintained files, source digest.

This is a **source-declared** inventory. It cannot enumerate transitive RPM
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

## Independent release intent

Release-bound OCI builds use:

```bash
tools/build-release-oci <planned-os-version> [--tag <image-reference>]
```

The wrapper owns the absolute repository context, its `Containerfile`, and the
two release-intent build arguments. Arbitrary Podman options and positional
contexts are intentionally unsupported. Callers that previously supplied `.`
must omit it; the wrapper now supplies the validated repository root itself.

Release-bound disk builds use:

```bash
image/build/build-qcow2.sh --release-intent <planned-os-version> \
  [local CoreOS OCI reference]
```

The planned OS version comes from the invocation, independently of source
identity strings. The host-side gate rejects missing, malformed, stale, or
conflicting release identities before Podman or disk construction. Direct
developer builds keep their established commands and current-tree identity,
but are not release-intent invocations and cannot establish release approval.
