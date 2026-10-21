#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PREFLIGHT = REPO / "tools/release-preflight"


class HistoricalReleasePreflightTests(unittest.TestCase):
    def replay(self, revision: str, planned: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar"
            with archive.open("wb") as output:
                subprocess.run(["git", "-C", str(REPO), "archive", revision], check=True, stdout=output)
            source = root / "source"
            source.mkdir()
            with tarfile.open(archive) as bundle:
                bundle.extractall(source, filter="data")
            return subprocess.run(
                [str(PREFLIGHT), planned, "--root", str(source)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    def test_invalid_four_component_cargo_version_is_rejected(self) -> None:
        result = self.replay("d835f5a", "0.0.3.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not valid SemVer", result.stderr)

    def test_pre_identity_fix_tree_is_rejected_for_maintenance_version(self) -> None:
        result = self.replay("ec7b9d4", "0.0.3.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Containerfile OCI version label", result.stderr)

    def test_valid_maintenance_candidate_passes(self) -> None:
        result = self.replay("e332e26", "0.0.3.1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_historical_release_passes_for_its_intended_version(self) -> None:
        result = self.replay("v0.0.3", "0.0.3")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
