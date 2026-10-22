#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
INVENTORY = REPO / "tools/coreos-inventory"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip())


def fixture(root: Path) -> None:
    write(
        root / "Cargo.toml",
        """
        [workspace]
        members = ["app"]
        resolver = "2"
        [workspace.package]
        version = "0.0.3"
        """,
    )
    write(root / "app/Cargo.toml", "[package]\nname='sl-app'\nversion.workspace=true\n")
    write(root / "image/platform/sl-app.service", "[Service]\nExecStart=/usr/bin/sl-app\n")
    write(root / "image/platform/sl-app.sysusers", 'u sl-app - "app" /nonexistent /usr/sbin/nologin\n')
    write(
        root / "image/platform/org.signallayer.App1.conf",
        """
        <busconfig>
          <policy context="default">
            <allow send_destination="org.signallayer.App1" send_interface="org.signallayer.App1" send_member="GetStatus"/>
          </policy>
        </busconfig>
        """,
    )
    write(root / "image/platform/selinux/sl_app.te", "policy_module(sl_app, 1.0.0)\n")
    write(root / "image/platform/selinux/sl_app.fc", "/usr/bin/sl-app -- gen_context(system_u:object_r:bin_t,s0)\n")
    write(
        root / "Containerfile",
        """
        FROM build.example/unused AS build
        FROM quay.example/coreos@sha256:111
        RUN dnf -y install --setopt=install_weak_deps=False audit && dnf clean all
        COPY --from=build /build/sl-app /usr/bin/sl-app
        COPY image/platform/sl-app.service /usr/lib/systemd/system/sl-app.service
        COPY image/platform/sl-app.sysusers /usr/lib/sysusers.d/sl-app.conf
        COPY image/platform/org.signallayer.App1.conf /usr/share/dbus-1/system.d/org.signallayer.App1.conf
        RUN ln -s ../sl-app.service /usr/lib/systemd/system/multi-user.target.wants/sl-app.service
        """,
    )


class CoreOSInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        fixture(self.root)
        candidate = self.root / "candidate.json"
        result = self.run_tool("--candidate-output", str(candidate))
        self.assertEqual(result.returncode, 0, result.stderr)
        baseline = json.loads(candidate.read_text())
        baseline["approval_status"] = "accepted"
        baseline["accepted_source"] = baseline.pop("candidate_source")
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
        candidate.unlink()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(INVENTORY), "--root", str(self.root), "--baseline", str(getattr(self, "baseline", self.root / "baseline.json")), *extra],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_change(self, needle: str) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(needle, result.stdout)

    def test_matching_inventory_passes_and_json_is_machine_readable(self) -> None:
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "pass")
        self.assertEqual(parsed["differences"], [])
        self.assertEqual(parsed["installed_artifact_inventory"], "unproven")

    def test_added_runtime_package_fails(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("install --setopt=install_weak_deps=False audit", "install --setopt=install_weak_deps=False audit podman"))
        self.assert_change("added: runtime_packages_declared[]")

    def test_failing_json_names_the_changed_surface(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace(" audit &&", " audit podman &&"))
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 1)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "fail")
        self.assertIn(
            {"kind": "added", "path": "runtime_packages_declared[]", "actual": "podman"},
            parsed["differences"],
        )

    def test_removed_runtime_package_fails(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace(" audit &&", " &&"))
        self.assert_change("removed: runtime_packages_declared[]")

    def test_added_systemd_service_fails(self) -> None:
        write(self.root / "image/platform/sl-extra.service", "[Service]\nExecStart=/usr/bin/true\n")
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "COPY image/platform/sl-extra.service /usr/lib/systemd/system/sl-extra.service\n")
        self.assert_change("added: systemd_units./usr/lib/systemd/system/sl-extra.service")

    def test_removed_systemd_service_fails(self) -> None:
        path = self.root / "Containerfile"
        path.write_text("\n".join(line for line in path.read_text().splitlines() if "COPY image/platform/sl-app.service" not in line) + "\n")
        self.assert_change("removed: systemd_units./usr/lib/systemd/system/sl-app.service")

    def test_changed_systemd_unit_fails(self) -> None:
        path = self.root / "image/platform/sl-app.service"
        path.write_text(path.read_text() + "NoNewPrivileges=yes\n")
        self.assert_change("changed: systemd_units./usr/lib/systemd/system/sl-app.service.sha256")

    def test_added_sysusers_identity_fails(self) -> None:
        path = self.root / "image/platform/sl-app.sysusers"
        path.write_text(path.read_text() + 'u sl-extra - "extra" /nonexistent /usr/sbin/nologin\n')
        self.assert_change("sysusers_entries./usr/lib/sysusers.d/sl-app.conf[]")

    def test_added_dbus_method_fails(self) -> None:
        path = self.root / "image/platform/org.signallayer.App1.conf"
        path.write_text(path.read_text().replace("</policy>", '<allow send_destination="org.signallayer.App1" send_interface="org.signallayer.App1" send_member="Mutate"/>\n</policy>'))
        self.assert_change("dbus_policy_rules./usr/share/dbus-1/system.d/org.signallayer.App1.conf[]")

    def test_added_cargo_component_fails(self) -> None:
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text().replace('["app"]', '["app", "extra"]'))
        write(self.root / "extra/Cargo.toml", "[package]\nname='sl-extra'\nversion.workspace=true\n")
        self.assert_change("added: cargo_components.sl-extra")

    def test_changed_selinux_input_fails(self) -> None:
        path = self.root / "image/platform/selinux/sl_app.te"
        path.write_text(path.read_text() + "allow domain self:process signal;\n")
        self.assert_change("changed: selinux_policy_inputs.image/platform/selinux/sl_app.te")

    def test_candidate_cannot_overwrite_baseline(self) -> None:
        result = self.run_tool("--candidate-output", str(self.baseline))
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to overwrite the accepted baseline", result.stderr)

    def test_unapproved_candidate_is_not_a_baseline(self) -> None:
        candidate = self.root / "candidate.json"
        result = self.run_tool("--candidate-output", str(candidate))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.baseline = candidate
        result = self.run_tool()
        self.assertEqual(result.returncode, 2)
        self.assertIn("not explicitly marked accepted", result.stderr)


if __name__ == "__main__":
    unittest.main()
