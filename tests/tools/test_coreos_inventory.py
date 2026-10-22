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
        COPY app /src/app
        RUN printf compiled > /build/sl-app
        FROM build.example/policy AS policy-build
        COPY image/platform/selinux /policy
        RUN make -C /policy sl_platformd.pp
        FROM quay.example/coreos@sha256:111
        RUN dnf -y install --setopt=install_weak_deps=False audit podman && dnf clean all
        COPY --from=build /build/sl-app /usr/bin/sl-app
        COPY --from=policy-build /policy/sl_platformd.pp /usr/share/selinux/packages/sl_platformd.pp
        COPY image/platform/sl-app.service /usr/lib/systemd/system/sl-app.service
        COPY image/platform/sl-app.sysusers /usr/lib/sysusers.d/sl-app.conf
        COPY image/platform/org.signallayer.App1.conf /usr/share/dbus-1/system.d/org.signallayer.App1.conf
        RUN printf '%s' safe > /usr/lib/signallayer/release
        RUN sed 's/a/b/' /tmp/input > /usr/lib/signallayer/config
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
        self.contract = self.root / "contract.json"
        result = subprocess.run(
            [
                str(INVENTORY),
                "--root",
                str(self.root),
                "--baseline",
                str(self.baseline),
                "--contract-candidate-output",
                str(self.contract),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(INVENTORY),
                "--root",
                str(self.root),
                "--baseline",
                str(getattr(self, "baseline", self.root / "baseline.json")),
                "--build-contract",
                str(getattr(self, "contract", self.root / "contract.json")),
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_change(self, needle: str) -> None:
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(needle, result.stdout)

    def assert_grammar_rejection(self, instruction: str, needle: str) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + instruction + "\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("build_contract.stages[]", result.stdout)

    def test_matching_inventory_passes_and_json_is_machine_readable(self) -> None:
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "pass")
        self.assertEqual(parsed["differences"], [])
        self.assertEqual(parsed["installed_artifact_inventory"], "unproven")

    def test_added_runtime_package_fails(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("install --setopt=install_weak_deps=False audit podman", "install --setopt=install_weak_deps=False audit podman skopeo"))
        self.assert_change("added: runtime_packages_declared[]")

    def test_failing_json_names_the_changed_surface(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace(" audit podman &&", " audit podman skopeo &&"))
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 1)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "fail")
        self.assertIn(
            {"kind": "added", "path": "runtime_packages_declared[]", "actual": "skopeo"},
            parsed["differences"],
        )

    def test_removed_runtime_package_fails(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace(" audit podman &&", " audit &&"))
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

    def test_alternate_dnf_install_syntax_is_rejected(self) -> None:
        self.assert_grammar_rejection("RUN dnf install -y podman", "unsupported runtime package operation")

    def test_package_removal_is_rejected(self) -> None:
        self.assert_grammar_rejection("RUN dnf -y remove audit", "unsupported runtime package operation")

    def test_unsupported_package_manager_is_rejected(self) -> None:
        self.assert_grammar_rejection("RUN microdnf install podman", "unsupported runtime package operation")

    def test_add_runtime_file_is_rejected(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "ADD image/platform/sl-app.service /usr/lib/systemd/system/sl-added.service\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unsupported Containerfile instruction", result.stderr)

    def test_unsupported_copy_forms_are_rejected(self) -> None:
        instructions = {
            "JSON": 'COPY ["image/platform/sl-app.service", "/usr/lib/systemd/system/sl-json.service"]',
            "multiple sources": "COPY image/platform/sl-app.service image/platform/sl-app.sysusers /usr/lib/systemd/system/",
            "unsupported flag": "COPY --chown=root:root image/platform/sl-app.service /usr/lib/systemd/system/sl-app.service",
            "unknown destination": "COPY image/platform/sl-app.service /etc/profile.d/sl-app.sh",
        }
        original = (self.root / "Containerfile").read_text()
        for label, instruction in instructions.items():
            with self.subTest(form=label):
                (self.root / "Containerfile").write_text(original + instruction + "\n")
                result = self.run_tool()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("COPY", result.stderr)

    def test_shell_generated_systemd_unit_is_rejected(self) -> None:
        self.assert_grammar_rejection(
            "RUN printf '[Service]\\nExecStart=/usr/bin/true\\n' > /usr/lib/systemd/system/sl-generated.service",
            "unsupported runtime mutation command",
        )

    def test_direct_writes_to_protected_policy_surfaces_are_rejected(self) -> None:
        instructions = {
            "D-Bus": "RUN touch /usr/share/dbus-1/system.d/untracked.conf",
            "sysusers": "RUN touch /usr/lib/sysusers.d/untracked.conf",
            "SELinux": "RUN touch /usr/share/selinux/packages/untracked.pp",
        }
        original = (self.root / "Containerfile").read_text()
        for label, instruction in instructions.items():
            with self.subTest(surface=label):
                (self.root / "Containerfile").write_text(original + instruction + "\n")
                result = self.run_tool()
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("build_contract.stages[]", result.stdout)

    def test_previously_untracked_runtime_mutation_is_rejected(self) -> None:
        self.assert_grammar_rejection(
            "RUN touch /usr/bin/untracked-runtime",
            "unsupported runtime mutation command",
        )

    def test_indirect_runtime_mutation_is_rejected(self) -> None:
        self.assert_grammar_rejection(
            'RUN touch "$RUNTIME_DESTINATION"',
            "unsupported runtime mutation command",
        )

    def test_complete_runtime_run_approval_rejects_shell_obfuscation(self) -> None:
        additions = {
            "pipeline": "RUN true | touch /usr/bin/hidden",
            "background": "RUN true & touch /usr/bin/hidden",
            "dollar substitution": "RUN printf '%s' \"$(touch /usr/bin/hidden)\"",
            "backtick substitution": "RUN printf '%s' `touch /usr/bin/hidden`",
            "redirection": "RUN printf x > /usr/bin/hidden",
            "awk write": "RUN awk 'BEGIN { print 1 > \"/usr/bin/hidden\" }'",
            "find exec": "RUN find /tmp -exec touch /usr/bin/hidden ';'",
            "find delete": "RUN find /tmp -delete",
            "case": "RUN case x in x) touch /usr/bin/hidden ;; esac",
            "variable": "RUN target=/usr/bin/hidden; touch \"$target\"",
            "glob": "RUN rm -f /usr/bin/sl-*",
            "indirection": "RUN command=touch; \"$command\" /usr/bin/hidden",
            "new run": "RUN true",
        }
        original = (self.root / "Containerfile").read_text()
        for label, instruction in additions.items():
            with self.subTest(label=label):
                (self.root / "Containerfile").write_text(original + instruction + "\n")
                result = self.run_tool()
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("build_contract.stages[]", result.stdout)

    def test_extra_operation_inside_approved_run_is_detected(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("&& dnf clean all", "&& touch /usr/bin/hidden && dnf clean all"))
        self.assert_change("build_contract.stages[]")

    def test_extra_operation_inside_approved_printf_or_sed_is_detected(self) -> None:
        original = (self.root / "Containerfile").read_text()
        attempts = (
            original.replace("printf '%s' safe >", "printf '%s' safe; touch /usr/bin/hidden; printf '%s' safe >"),
            original.replace("sed 's/a/b/' /tmp/input >", "sed 's/a/b/' /tmp/input; touch /usr/bin/hidden; sed 's/a/b/' /tmp/input >"),
        )
        for changed in attempts:
            (self.root / "Containerfile").write_text(changed)
            self.assert_change("build_contract.stages[]")

    def test_from_inside_continued_run_is_not_a_stage_boundary(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "RUN printf x \\\nFROM attacker.example/image\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("build_contract.stages[]", result.stdout)
        self.assertNotIn("runtime_base_image", result.stdout)

    def test_unsupported_instruction_casing_is_rejected(self) -> None:
        original = (self.root / "Containerfile").read_text()
        for spelling in ("run", "Run"):
            with self.subTest(spelling=spelling):
                (self.root / "Containerfile").write_text(original + f"{spelling} true\n")
                result = self.run_tool()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("unsupported instruction casing", result.stderr)

    def test_additional_stage_and_alternate_runtime_base_are_detected(self) -> None:
        original = (self.root / "Containerfile").read_text()
        (self.root / "Containerfile").write_text(original + "FROM extra.example/base AS unexpected\n")
        self.assert_change("build_contract.stages[]")
        (self.root / "Containerfile").write_text(original.replace("quay.example/coreos@sha256:111", "quay.example/coreos@sha256:222"))
        self.assert_change("runtime_base_image")

    def test_malformed_continuation_is_rejected(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "RUN true \\\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("dangling", result.stderr)

    def test_copy_provenance_and_intermediate_stages_are_bound(self) -> None:
        original = (self.root / "Containerfile").read_text()
        attempts = {
            "changed stage": original.replace("--from=build /build/sl-app", "--from=policy-build /build/sl-app"),
            "external stage": original.replace("--from=build /build/sl-app", "--from=registry.example/image /build/sl-app"),
            "post compile mutation": original.replace(
                "RUN printf compiled > /build/sl-app",
                "RUN printf compiled > /build/sl-app\nRUN printf changed >> /build/sl-app",
            ),
            "policy build mutation": original.replace(
                "RUN make -C /policy sl_platformd.pp",
                "RUN make -C /policy sl_platformd.pp && printf changed >> /policy/sl_platformd.pp",
            ),
        }
        for label, changed in attempts.items():
            with self.subTest(label=label):
                (self.root / "Containerfile").write_text(changed)
                result = self.run_tool()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue("build_contract.stages[]" in result.stdout or "unknown or external stage" in result.stderr)

    def test_stage_alias_collision_is_rejected(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text().replace("AS policy-build", "AS build"))
        result = self.run_tool()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("duplicate or ambiguous stage alias", result.stderr)

    def test_maintained_build_source_change_is_detected(self) -> None:
        path = self.root / "app/Cargo.toml"
        path.write_text(path.read_text() + "description='changed'\n")
        self.assert_change("build_contract.build_context_inputs.app/Cargo.toml")

    def test_copy_inventory_records_exact_source_stage(self) -> None:
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        contract = json.loads(self.contract.read_text())["contract"]
        executable = next(item for item in contract["copy_provenance"] if item["destination"] == "/usr/bin/sl-app")
        self.assertEqual(executable["from"], "build")

    def test_parser_error_is_machine_readable(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "ADD payload /usr/bin/untracked\n")
        result = self.run_tool("--format", "json")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "error")
        self.assertIn("unsupported Containerfile instruction", parsed["error"])

    def test_candidate_generation_cannot_bypass_runtime_parser(self) -> None:
        path = self.root / "Containerfile"
        path.write_text(path.read_text() + "RUN touch /usr/bin/untracked-runtime\n")
        candidate = self.root / "unapproved.json"
        result = self.run_tool("--candidate-output", str(candidate))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(candidate.exists())
        result = self.run_tool()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("build_contract.stages[]", result.stdout)

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
