"""Source-only P3-1c preflight binding, independent of rootfs fixture execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import test_planned_inventory as planned


class RootfsInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.context = planned.PlannedInventoryTests.preflight_copy_context(self)

    def gate(self):
        return planned.PlannedInventoryTests.run_context_gate(None, self.context)

    def test_source_tools_and_recipe_bound_in_real_preflight_context(self):
        contract = json.loads((self.context/planned.inv.DEFAULT_BUILD_CONTRACT).read_text())['contract']
        for name in ('tools/build-management-rootfs', 'tools/verify-management-rootfs',
                     'management-fixture/rootfs-spec.json', 'management-fixture/src/main.rs',
                     'management-fixture/inputs/message.txt'):
            item = contract['planned_source_inputs'][name]
            self.assertEqual(item['sha256'], hashlib.sha256((self.context/name).read_bytes()).hexdigest())
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_modified_independent_verifier_rejected(self):
        path = self.context/'tools/verify-management-rootfs'
        path.write_text(path.read_text()+'\n# unreviewed change\n')
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('tools/verify-management-rootfs', result.stdout+result.stderr)

    def test_missing_recipe_copy_rejected(self):
        (self.context/'management-fixture/rootfs-spec.json').unlink()
        result = self.gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('management-fixture/rootfs-spec.json', result.stdout+result.stderr)

    def test_fixture_and_oracle_not_installed(self):
        measured = planned.inv.collect(planned.REPO)
        self.assertNotIn('sl-management-fixture', measured['cargo_components'])
        self.assertFalse(any('management-rootfs' in str(value) for value in measured['coreos_executables'].values()))
        self.assertEqual(measured, json.loads((planned.REPO/planned.inv.DEFAULT_BASELINE).read_text())['inventory'])


if __name__ == '__main__':
    unittest.main()
