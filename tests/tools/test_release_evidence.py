#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools/release-evidence"
VERSION = "0.0.3.1"
SOURCE = "a" * 40
BUILD_ID = f"{VERSION}-{SOURCE[:12]}-release"
IMAGE_ID = "sha256:" + "1" * 64
REFERENCE = "localhost/signallayer-coreos:0.0.3.1"


def write_inspection(path: Path, **changes: object) -> None:
    labels = {
        "containers.bootc": "1",
        "org.opencontainers.image.title": "SignalLayerIT CoreOS",
        "org.opencontainers.image.version": VERSION,
        "org.opencontainers.image.revision": SOURCE,
        "org.signallayer.image.build-id": BUILD_ID,
    }
    labels.update(changes.pop("labels", {}))
    value = {
        "Id": IMAGE_ID,
        "Digest": "sha256:" + "2" * 64,
        "RepoDigests": ["example@sha256:" + "2" * 64],
        "Config": {"Labels": labels},
        **changes,
    }
    path.write_text(json.dumps([value]))


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inspection = self.root / "inspection.json"
        self.record = self.root / "record.json"
        write_inspection(self.inspection)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(TOOL),
                "create",
                "--inspection",
                str(self.inspection),
                "--output",
                str(self.record),
                "--planned-version",
                VERSION,
                "--source-commit",
                SOURCE,
                "--build-id",
                BUILD_ID,
                "--image-reference",
                REFERENCE,
                "--containerfile-sha256",
                "3" * 64,
                "--wrapper-sha256",
                "4" * 64,
                "--podman-version",
                "podman fixture",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def verify(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        values = {
            "inspection": str(self.inspection),
            "record": str(self.record),
            "planned": VERSION,
            "source": SOURCE,
            "reference": REFERENCE,
            **overrides,
        }
        return subprocess.run(
            [
                "python3",
                str(TOOL),
                "verify",
                "--inspection",
                values["inspection"],
                "--record",
                values["record"],
                "--planned-version",
                values["planned"],
                "--source-commit",
                values["source"],
                "--image-reference",
                values["reference"],
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_controlled_record_round_trip_binds_immutable_image(self) -> None:
        created = self.create()
        self.assertEqual(created.returncode, 0, created.stderr)
        verified = self.verify()
        self.assertEqual(verified.returncode, 0, verified.stderr)
        record = json.loads(self.record.read_text())
        self.assertEqual(record["image_id"], IMAGE_ID)
        self.assertEqual(record["trust"], "trusted-local-build-host; no cryptographic attestation")

    def test_developer_image_with_public_version_labels_is_rejected(self) -> None:
        write_inspection(
            self.inspection,
            labels={
                "org.opencontainers.image.revision": "unknown",
                "org.signallayer.image.build-id": "0.0.3.1-local",
            },
        )
        result = self.create()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("revision", result.stderr)

    def test_record_mismatch_controls(self) -> None:
        self.assertEqual(self.create().returncode, 0)
        cases = {
            "source": {"source": "b" * 40, "message": "source_commit"},
            "version": {"planned": "0.0.4", "message": "planned_os_version"},
            "tag": {"reference": "localhost/other:0.0.3.1", "message": "image_reference"},
        }
        for label, values in cases.items():
            with self.subTest(label=label):
                message = values.pop("message")
                result = self.verify(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_different_image_id_and_label_are_rejected(self) -> None:
        self.assertEqual(self.create().returncode, 0)
        write_inspection(self.inspection, Id="sha256:" + "9" * 64)
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable ID", result.stderr)
        write_inspection(self.inspection, labels={"org.opencontainers.image.title": "Impostor"})
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image.title", result.stderr)

    def test_missing_malformed_and_forged_record_fail(self) -> None:
        missing = self.verify()
        self.assertNotEqual(missing.returncode, 0)
        self.record.write_text("not json")
        malformed = self.verify()
        self.assertNotEqual(malformed.returncode, 0)
        self.record.write_text(json.dumps({"schema": "forged", "release_intent": True}))
        forged = self.verify()
        self.assertNotEqual(forged.returncode, 0)
        self.assertIn("malformed", forged.stderr)

    def test_missing_build_id_and_output_inspection_failure_fail(self) -> None:
        write_inspection(self.inspection, labels={"org.signallayer.image.build-id": ""})
        result = self.create()
        self.assertNotEqual(result.returncode, 0)
        self.inspection.write_text("not json")
        result = self.create()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("valid JSON", result.stderr)

    def test_invalid_or_unknown_source_revision_fails(self) -> None:
        for source in ("unknown", "", "A" * 40, "a" * 39):
            with self.subTest(source=source):
                result = subprocess.run(
                    [
                        "python3",
                        str(TOOL),
                        "create",
                        "--inspection",
                        str(self.inspection),
                        "--output",
                        str(self.record),
                        "--planned-version",
                        VERSION,
                        "--source-commit",
                        source,
                        "--build-id",
                        BUILD_ID,
                        "--image-reference",
                        REFERENCE,
                        "--containerfile-sha256",
                        "3" * 64,
                        "--wrapper-sha256",
                        "4" * 64,
                        "--podman-version",
                        "fixture",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("source commit", result.stderr)

    def test_record_is_never_overwritten(self) -> None:
        self.record.write_text("preserve\n")
        result = self.create()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.record.read_text(), "preserve\n")


if __name__ == "__main__":
    unittest.main()
