#!/usr/bin/env python3
"""Apply the image's physical OSTree directory label during OSBuild construction."""
import copy
import json
import sys
from pathlib import Path


def prepare(manifest, label):
    if label != "system_u:object_r:sl_platformd_ostree_t:s0":
        raise ValueError("Source image must provide the dedicated OSTree directory context")
    result = copy.deepcopy(manifest)
    pipelines = [p for p in result["pipelines"] if p["name"] == "image"]
    if len(pipelines) != 1:
        raise ValueError("Expected one Image Builder physical image pipeline")
    pipeline = pipelines[0]
    installs = [s for s in pipeline["stages"]
                if s["type"] == "org.osbuild.bootc.install-to-filesystem"]
    if len(installs) != 1:
        raise ValueError("Expected one bootc filesystem installation")
    install = installs[0]
    roots = [m for m in install["mounts"] if m["name"] == "-" and m["target"] == "/"]
    if len(roots) != 1 or roots[0]["type"] != "org.osbuild.ext4":
        raise ValueError("Expected the maintained ext4 physical-root mount")
    pipeline["stages"].append({
        "type": "org.osbuild.selinux",
        "options": {"labels": {"mount://-/ostree": label}},
        "devices": copy.deepcopy(install["devices"]),
        "mounts": copy.deepcopy(roots),
    })
    return result


if __name__ == "__main__":
    source, context, destination = map(Path, sys.argv[1:])
    destination.write_text(json.dumps(prepare(json.loads(source.read_text()),
                                            context.read_text().strip()), indent=2) + "\n")
