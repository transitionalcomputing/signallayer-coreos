"""P3-1b source gate controls; no identity or image mutation."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import test_planned_inventory as planned


class IdentityInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.context = planned.PlannedInventoryTests.preflight_copy_context(self)

    def gate(self):
        return planned.PlannedInventoryTests.run_context_gate(None,self.context)

    def test_identity_sources_are_bound_in_real_preflight_context(self):
        contract=json.loads((self.context/planned.inv.DEFAULT_BUILD_CONTRACT).read_text())["contract"]
        for source in ("management-lifecycle/identity.py","management-lifecycle/README.md"):
            item=contract["planned_source_inputs"][source]
            self.assertFalse(item["executable"])
            self.assertEqual(item["sha256"],hashlib.sha256((self.context/source).read_bytes()).hexdigest())
        result=self.gate()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_modified_provisioner_fails_source_gate(self):
        path=self.context/"management-lifecycle/identity.py"
        path.write_text(path.read_text()+"\n# unauthorized edit\n")
        result=self.gate()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("management-lifecycle/identity.py",result.stdout+result.stderr)

    def test_missing_preflight_source_copy_is_not_silently_absent(self):
        (self.context/"management-lifecycle/identity.py").unlink()
        result=self.gate()
        self.assertNotEqual(result.returncode,0)
        self.assertIn("management-lifecycle/identity.py",result.stdout+result.stderr)

    def test_provisioner_not_installed_or_added_to_workspace(self):
        measured=planned.inv.collect(planned.REPO)
        self.assertNotIn("sl-management-lifecycle",measured["cargo_components"])
        self.assertFalse(any("management-lifecycle" in str(value)
                             for value in measured["coreos_executables"].values()))
        baseline=json.loads((planned.REPO/planned.inv.DEFAULT_BASELINE).read_text())
        self.assertEqual(baseline["planned_inventory"]["identity_provisioning_source"]["status"],
                         "source-only-not-installed")


if __name__=="__main__":
    unittest.main()
