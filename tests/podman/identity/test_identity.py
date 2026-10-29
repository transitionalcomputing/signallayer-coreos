"""Executable P3-1b parser/transaction fixtures, never live account changes."""
import importlib.util
from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("p31b_identity", ROOT / "management-lifecycle/identity.py")
identity = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = identity
spec.loader.exec_module(identity)


class Interrupted(Exception):
    pass


class NSSFixtureStore(identity._Store):
    def check_sources(self):
        identity._HostStore.check_sources(self)

    def check_choice(self, chosen):
        identity._HostStore.check_choice(self, chosen)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir(mode=0o755)
        self.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
        self.write("etc/group", "root:x:0:\n")
        self.write("etc/shadow", "root:!:0:0:99999:7:::\n")
        self.write("etc/gshadow", "root:!::\n")
        self.write("etc/subuid", "")
        self.write("etc/subgid", "")

    def write(self, path, data, mode=None):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        if mode is None:
            mode = 0o600 if path in ("etc/shadow", "etc/gshadow", identity.METADATA) else 0o644
        p.chmod(mode)

    def add_user(self, name, uid, gid=None):
        if gid is None:
            gid = uid
        for path, line in {
            "etc/passwd": f"{name}:x:{uid}:{gid}::{self.root}/unused:/usr/sbin/nologin\n",
            "etc/group": f"{name}:x:{gid}:\n",
            "etc/shadow": f"{name}:!:0:0:99999:7:::\n",
            "etc/gshadow": f"{name}:!::\n",
        }.items():
            self.write(path, (self.root/path).read_bytes() + line.encode())

    def store(self, cls=identity._Store):
        store = cls(str(self.root), os.getuid(), os.getgid())
        self.addCleanup(store.close)
        return store

    def run_provision(self, cls=identity._Store):
        store = self.store(cls)
        try:
            return identity._provision(store)
        finally:
            store.close()

    def raw(self):
        return {p: (self.root/p).read_bytes() if (self.root/p).exists() else None for p in identity.FILES}

    def assert_rejected(self, needle):
        before = self.raw()
        with self.assertRaisesRegex(identity.IdentityError, needle):
            self.run_provision()
        self.assertEqual(before, self.raw(), "rejection mutated account databases")

    def test_empty_machine_creates_locked_identity_and_maps(self):
        chosen = self.run_provision()
        snapshot = identity.read_validate(self.raw())
        identity._verify(snapshot, chosen)
        self.assertNotEqual(chosen.uid, 0)
        self.assertEqual(chosen.count, 65536)
        self.assertEqual(chosen.subuid % 65536, 0)
        self.assertGreaterEqual(chosen.subuid, 100000)
        self.assertEqual(snapshot.passwd[identity.NAME][5:], [identity.HOME, identity.SHELL])
        self.assertNotIn("sl-runtime", snapshot.passwd)
        record = json.loads((self.root/identity.METADATA).read_text())
        self.assertEqual(set(record), {"schema", "phase", "identity"})
        self.assertEqual(record["phase"], "committed")
        self.assertEqual(stat.S_IMODE((self.root/identity.METADATA).stat().st_mode), 0o600)

    def test_consistent_existing_accepted_identity_is_idempotent(self):
        expected = self.run_provision()
        before = self.raw()
        metadata = (self.root/identity.METADATA).read_bytes()
        for _ in range(3):
            self.assertEqual(self.run_provision(), expected)
            self.assertEqual(self.raw(), before)
            self.assertEqual((self.root/identity.METADATA).read_bytes(), metadata)

    def test_simulated_reboot_and_A_B_A_preserve_identity(self):
        expected = self.run_provision()
        for build in ("A", "B", "A"):
            self.write("etc/test-build", build)
            self.assertEqual(self.run_provision(), expected)
        # Source-only fresh-store replay, not actual system reboot/lifecycle proof.

    def test_occupied_uid_976_selects_free_identity(self):
        for uid in range(976, 1000):
            self.add_user(f"other{uid}", uid)
        chosen = self.run_provision()
        self.assertEqual(chosen.uid, 975)

    def test_occupied_gid_selects_free_identity(self):
        self.write("etc/group", "root:x:0:\nreserved:x:999:\n")
        self.write("etc/gshadow", "root:!::\nreserved:!::\n")
        self.assertEqual(self.run_provision().gid, 998)

    def test_unrecorded_account_is_not_adopted(self):
        self.add_user(identity.NAME, 700)
        self.assert_rejected("ambiguous pre-existing")

    def test_unrecorded_group_collision_is_not_adopted(self):
        self.write("etc/group", "root:x:0:\nsl-management:x:700:\n")
        self.write("etc/gshadow", "root:!::\nsl-management:!::\n")
        self.assert_rejected("ambiguous pre-existing")

    def test_reserved_future_identity_and_unrelated_entries_preserved(self):
        self.add_user("sl-runtime", 999)
        self.write("etc/subuid", "sl-runtime:131072:65536\n")
        self.write("etc/subgid", "sl-runtime:131072:65536\n")
        before = self.raw()
        chosen = self.run_provision()
        self.assertEqual(chosen.uid, 998)
        self.assertEqual(chosen.subuid, 196608)
        for path in identity.FILES:
            self.assertTrue(self.raw()[path].startswith(before[path]))

    def test_allocator_excludes_both_uid_and_gid_maps_and_boundaries(self):
        self.add_user("alice", 1000)
        self.add_user("bob", 1001)
        self.write("etc/subuid", "alice:131071:2\n")
        self.write("etc/subgid", "bob:262143:2\n")
        chosen = self.run_provision()
        self.assertEqual(chosen.subuid, 327680)
        self.assertEqual(chosen.subgid, 327680)

    def test_live_primary_ids_excluded_from_subordinate_allocation(self):
        self.add_user("large", 131072)
        self.assertEqual(self.run_provision().subuid, 196608)

    def test_overlapping_existing_subids_rejected_at_start_and_end(self):
        self.add_user("alice", 1000)
        self.add_user("bob", 1001)
        for entry in ("bob:131072:1\n", "bob:196607:1\n"):
            with self.subTest(entry=entry):
                self.write("etc/subuid", "alice:131072:65536\n" + entry)
                self.assert_rejected("overlapping")

    def test_subgid_collision_is_not_ignored(self):
        self.add_user("alice", 1000)
        self.add_user("bob", 1001)
        self.write("etc/subgid", "alice:131072:65536\nbob:196607:1\n")
        self.assert_rejected("overlapping")

    def test_subordinate_extent_over_live_primary_id_rejected(self):
        self.add_user("alice", 1000)
        self.write("etc/subuid", "root:999:2\n")
        self.assert_rejected("overlaps a live primary")

    def test_numeric_mapping_owner_resolves_without_duplicate_alias(self):
        self.add_user("alice", 1000)
        self.write("etc/subuid", "1000:131072:65536\n")
        self.assertEqual(self.run_provision().subuid, 196608)

    def test_missing_owner_malformed_duplicate_partial_and_overflow_rejected(self):
        self.add_user("alice", 1000)
        cases = ["missing:131072:65536\n", "404:131072:65536\n", "alice:0:1\n",
                 "alice:131072:0\n", "alice:131072:-1\n", "alice:131072:4294967295\n",
                 "alice:4294967295:1\n", "alice:131072:65536", "alice:bad:65536\n",
                 "alice:131072:65536:extra\n", "alice:131072:65536\nalice:262144:65536\n",
                 "alice:131072:65536\n1000:262144:65536\n", "alice:131072:65536\r\n"]
        for record in cases:
            with self.subTest(record=record):
                self.write("etc/subuid", record)
                self.assert_rejected("owner missing|record|extent|identity")

    def test_no_remaining_system_identity_refuses(self):
        for uid in range(100, 1000):
            self.add_user(f"account{uid}", uid)
        self.assert_rejected("no free machine-local")

    def test_subid_space_exhaustion_refuses(self):
        self.write("etc/subuid", f"root:100000:{identity.MAX_ID-99999}\n")
        self.assert_rejected("no free subordinate")

    def test_duplicate_names_and_numeric_ids_fail(self):
        self.add_user("alice", 1000)
        self.write("etc/passwd", (self.root/"etc/passwd").read_bytes() + b"alice:x:1001:1000::/:/bin/false\n")
        self.assert_rejected("duplicate")

    def test_duplicate_numeric_identity_fails(self):
        self.add_user("alice", 1000)
        self.write("etc/passwd", (self.root/"etc/passwd").read_bytes() + b"bob:x:1000:1000::/:/bin/false\n")
        self.assert_rejected("duplicate numeric")

    def test_malformed_and_missing_databases_fail(self):
        self.write("etc/shadow", "root:!:partial\n")
        self.assert_rejected("malformed")
        (self.root/"etc/shadow").unlink()
        self.assert_rejected("missing account")

    def test_absent_subid_files_can_be_created(self):
        for path in ("etc/subuid", "etc/subgid"):
            (self.root/path).unlink()
        self.run_provision()
        self.assertTrue((self.root/"etc/subuid").is_file())
        self.assertTrue((self.root/"etc/subgid").is_file())

    def test_every_durable_transaction_boundary_recovers(self):
        original = self.raw()
        for failure in range(1, 9):
            with self.subTest(after_write=failure), tempfile.TemporaryDirectory() as temp:
                # Each iteration uses a fresh copy of the same empty fixture.
                import shutil
                for child in self.root.iterdir():
                    if child.is_dir():
                        shutil.copytree(child, Path(temp)/child.name)
                real_root = self.root
                self.root = Path(temp)
                class Cut(identity._Store):
                    writes = 0
                    def after_write(self, path):
                        self.writes += 1
                        if self.writes == failure:
                            raise Interrupted()
                try:
                    with self.assertRaises(Interrupted):
                        self.run_provision(Cut)
                    chosen = self.run_provision()
                    identity._verify(identity.read_validate(self.raw()), chosen)
                    for path in identity.FILES:
                        self.assertTrue(self.raw()[path].startswith(original[path]))
                finally:
                    self.root = real_root

    def interrupt_after_intent(self):
        class Cut(identity._Store):
            def after_write(self, path):
                raise Interrupted()
        with self.assertRaises(Interrupted):
            self.run_provision(Cut)

    def test_prepared_metadata_has_no_credential_copies(self):
        self.interrupt_after_intent()
        record = json.loads((self.root/identity.METADATA).read_text())
        self.assertEqual(record["phase"], "prepared")
        for item in record["files"].values():
            self.assertEqual(set(item), {"before", "after"})
        self.assertNotIn("root:!", (self.root/identity.METADATA).read_text())

    def test_interruption_with_unrelated_change_refuses_without_rollback(self):
        self.interrupt_after_intent()
        self.add_user("newoperator", 1200)
        self.assert_rejected("transaction conflicts")
        self.assertIn(b"newoperator", (self.root/"etc/passwd").read_bytes())

    def test_unrelated_account_change_after_commit_is_preserved(self):
        expected = self.run_provision()
        self.add_user("operator", 1200)
        before = self.raw()
        self.assertEqual(self.run_provision(), expected)
        self.assertEqual(self.raw(), before)

    def test_runtime_state_without_metadata_blocks_allocation(self):
        (self.root/identity.STATE[0]).mkdir(parents=True)
        self.assert_rejected("state exists without accepted identity")

    def test_runtime_state_during_partial_transaction_refuses(self):
        self.interrupt_after_intent()
        (self.root/identity.STATE[1]).mkdir()
        self.assert_rejected("partial identity with runtime/application state")

    def test_changed_identity_after_app_state_refuses(self):
        chosen = self.run_provision()
        (self.root/identity.STATE[0]).mkdir()
        path = self.root/"etc/passwd"
        self.write("etc/passwd", path.read_text().replace(f"sl-management:x:{chosen.uid}:", "sl-management:x:700:"))
        self.assert_rejected("identity/shell/credentials drift")

    def test_changed_maps_after_app_state_refuses(self):
        chosen = self.run_provision()
        (self.root/identity.STATE[0]).mkdir()
        self.write("etc/subuid", f"sl-management:{chosen.subuid+65536}:65536\n")
        self.assert_rejected("mapping drift")

    def test_unsupported_shell_and_unlocked_password_refuse(self):
        self.run_provision()
        original = self.raw()
        self.write("etc/passwd", original["etc/passwd"].replace(identity.SHELL.encode(), b"/bin/bash"))
        self.assert_rejected("identity/shell/credentials drift")
        self.write("etc/passwd", original["etc/passwd"])
        self.write("etc/shadow", original["etc/shadow"].replace(b"sl-management:!:", b"sl-management:$6$hash:"))
        self.assert_rejected("identity/shell/credentials drift")

    def test_supplementary_admin_group_refuses(self):
        self.run_provision()
        self.write("etc/group", (self.root/"etc/group").read_bytes()+b"wheel:x:10:sl-management\n")
        self.write("etc/gshadow", (self.root/"etc/gshadow").read_bytes()+b"wheel:!::sl-management\n")
        self.assert_rejected("supplementary group")

    def test_gshadow_admin_membership_refuses(self):
        self.run_provision()
        self.write("etc/group", (self.root/"etc/group").read_bytes()+b"wheel:x:10:\n")
        self.write("etc/gshadow", (self.root/"etc/gshadow").read_bytes()+b"wheel:!:sl-management:\n")
        self.assert_rejected("administrator/member")

    def test_symlink_file_and_ancestor_substitution_refuse(self):
        original = self.raw()["etc/subuid"]
        outside = self.root/"outside"
        outside.write_bytes(original)
        (self.root/"etc/subuid").unlink()
        (self.root/"etc/subuid").symlink_to(outside)
        with self.assertRaises(OSError):
            self.run_provision()
        (self.root/"etc/subuid").unlink()
        self.write("etc/subuid", original)
        (self.root/"etc").rename(self.root/"real-etc")
        (self.root/"etc").symlink_to(self.root/"real-etc", target_is_directory=True)
        with self.assertRaisesRegex(identity.IdentityError, "lock unavailable"):
            self.run_provision()
        self.assertEqual((self.root/"real-etc/passwd").read_bytes(), b"root:x:0:0:root:/root:/bin/bash\n")

    def test_hardlink_and_wrong_object_type_refuse(self):
        os.link(self.root/"etc/passwd", self.root/"alias")
        self.assert_rejected("hardlink")
        (self.root/"alias").unlink()
        (self.root/"etc/subuid").unlink()
        (self.root/"etc/subuid").mkdir()
        with self.assertRaisesRegex(identity.IdentityError, "file type"):
            self.run_provision()

    def test_wrong_owner_fails_actual_metadata_validator(self):
        store = self.store()
        fd = os.open(self.root/"etc/passwd", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        store.uid = os.getuid()+1
        with self.assertRaisesRegex(identity.IdentityError, "ownership"):
            store._check(fd)

    def test_wrong_group_owner_refuses(self):
        store = self.store()
        fd = os.open(self.root/"etc/passwd", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        store.gid = os.getgid()+1
        with self.assertRaisesRegex(identity.IdentityError, "ownership"):
            store._check(fd)

    def test_fifo_is_rejected_without_blocking(self):
        p = self.root/"etc/subuid"
        p.unlink()
        os.mkfifo(p, 0o600)
        with self.assertRaisesRegex(identity.IdentityError, "file type"):
            self.run_provision()

    def test_untrusted_file_and_directory_permissions_refuse(self):
        for path, mode in (("etc/passwd", 0o666), ("etc/shadow", 0o644), ("etc", 0o777)):
            with self.subTest(path=path):
                p=self.root/path
                before=stat.S_IMODE(p.stat().st_mode)
                p.chmod(mode)
                self.assert_rejected("mode")
                p.chmod(before)

    def test_approved_permissions_and_umask_do_not_pin_exact_bits(self):
        for path in identity.FILES:
            if path not in ("etc/shadow", "etc/gshadow"):
                (self.root/path).chmod(0o600)
        previous = os.umask(0o077)
        try:
            chosen = self.run_provision()
        finally:
            os.umask(previous)
        for path in identity.FILES:
            if path not in ("etc/shadow", "etc/gshadow"):
                (self.root/path).chmod(0o644)
        self.assertEqual(self.run_provision(), chosen)

    def test_private_metadata_permissions_and_symlink_refuse(self):
        self.run_provision()
        p = self.root/identity.METADATA
        p.chmod(0o644)
        self.assert_rejected("mode")
        p.chmod(0o600)
        p.rename(p.with_name("saved.json"))
        p.symlink_to(p.with_name("saved.json"))
        with self.assertRaises(OSError):
            self.run_provision()

    def test_metadata_schema_duplicates_and_overflow_refuse(self):
        self.run_provision()
        original=json.loads((self.root/identity.METADATA).read_text())
        for key,value in (("schema",2),("phase","unknown"),("identity",{"uid":0}),("identity",{"uid":999,"gid":999,"subuid":4294967295,"subgid":131072,"count":65536})):
            record=dict(original);record[key]=value
            self.write(identity.METADATA,json.dumps(record))
            self.assert_rejected("metadata|schema|phase")
        self.write(identity.METADATA,'{"schema":1,"schema":1}')
        self.assert_rejected("duplicate recovery")

    def test_lock_contention_refuses_without_database_changes(self):
        store = self.store()
        store.locked()
        before = self.raw()
        with self.assertRaisesRegex(identity.IdentityError, "lock unavailable"):
            self.run_provision()
        self.assertEqual(before,self.raw())

    def test_late_concurrent_change_detected_before_overwrite(self):
        class Change(identity._Store):
            def after_write(inner,path):
                if path==identity.METADATA:
                    self.add_user("racer",1200)
        with self.assertRaisesRegex(identity.IdentityError,"concurrent identity-file change"):
            self.run_provision(Change)
        self.assertIn(b"racer",(self.root/"etc/passwd").read_bytes())

    def test_live_entry_root_and_arbitrary_arguments_rejected(self):
        with mock.patch.object(identity.os,"geteuid",return_value=1000):
            with self.assertRaisesRegex(identity.IdentityError,"requires host root"):
                identity.provision()
        with self.assertRaises(TypeError):
            identity.provision(root=str(self.root))
        with self.assertRaises(TypeError):
            identity.provision("/bin/sh")

    def test_umask_002_does_not_change_identity_or_private_state(self):
        previous = os.umask(0o002)
        try:
            chosen = self.run_provision()
        finally:
            os.umask(previous)
        self.assertEqual(self.run_provision(), chosen)
        self.assertEqual(stat.S_IMODE((self.root/identity.METADATA).stat().st_mode), 0o600)

    def test_nss_files_policy_positive_and_unknown_provider_negative(self):
        identity._nss_policy(b"passwd: files systemd\ngroup: files systemd\nshadow: files\n")
        for data in (None, b"passwd: sss files\ngroup: files\nshadow: files\n",
                     b"passwd: files\ngroup: files ldap\nshadow: files\n",
                     b"passwd: files\ngroup: files\n", b"passwd: files\npasswd: files\ngroup: files\nshadow: files\n"):
            with self.subTest(policy=data), self.assertRaises(identity.IdentityError):
                identity._nss_policy(data)

    def test_executable_or_capability_bearing_database_refuses(self):
        p=self.root/"etc/passwd"
        p.chmod(0o744)
        self.assert_rejected("mode")
        p.chmod(0o644)
        store=self.store()
        fd=os.open(p,os.O_RDONLY)
        self.addCleanup(os.close,fd)
        with mock.patch.object(identity.os,"listxattr",return_value=["security.capability"]):
            with self.assertRaisesRegex(identity.IdentityError,"capability"):
                store._check(fd)

    def test_short_reads_are_completed_before_parsing(self):
        real_read=identity.os.read
        with mock.patch.object(identity.os,"read",side_effect=lambda fd,size: real_read(fd,min(size,7))):
            chosen=self.run_provision()
        identity._verify(identity.read_validate(self.raw()),chosen)

    def test_extremely_large_numeric_field_is_structured_refusal(self):
        self.write("etc/subuid","root:"+"9"*5000+":65536\n")
        self.assert_rejected("overflowing numeric")

    def test_existing_xattrs_and_modes_survive_replacement(self):
        p=self.root/"etc/passwd"
        os.setxattr(p,"user.sl_identity_test",b"preserved")
        p.chmod(0o640)
        self.run_provision()
        self.assertEqual(os.getxattr(p,"user.sl_identity_test"),b"preserved")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o640)

    def test_actual_nss_lookup_collision_is_rejected(self):
        from types import SimpleNamespace
        chosen = identity.Identity(999, 999, 131072, 131072)
        with mock.patch.object(identity.pwd, "getpwall", return_value=[]), mock.patch.object(identity.grp, "getgrall", return_value=[]), mock.patch.object(identity.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="outside")):
            with self.assertRaisesRegex(identity.IdentityError, "NSS identity collision"):
                identity._HostStore.check_choice(None, chosen)

    def test_nss_mapping_collision_and_membership_are_rejected(self):
        from types import SimpleNamespace
        chosen = identity.Identity(999, 999, 131072, 131072)
        with mock.patch.object(identity.pwd, "getpwall", return_value=[SimpleNamespace(pw_uid=131072)]), mock.patch.object(identity.grp, "getgrall", return_value=[]), mock.patch.object(identity.pwd, "getpwuid", side_effect=KeyError), mock.patch.object(identity.grp, "getgrgid", side_effect=KeyError), mock.patch.object(identity.pwd, "getpwnam", side_effect=KeyError), mock.patch.object(identity.grp, "getgrnam", side_effect=KeyError):
            with self.assertRaisesRegex(identity.IdentityError,"overlaps proposed mappings"):
                identity._HostStore.check_choice(None,chosen)
        with mock.patch.object(identity.pwd, "getpwall", return_value=[]), mock.patch.object(identity.grp, "getgrall", return_value=[SimpleNamespace(gr_gid=10,gr_mem=[identity.NAME])]), mock.patch.object(identity.pwd, "getpwuid", side_effect=KeyError), mock.patch.object(identity.grp, "getgrgid", side_effect=KeyError), mock.patch.object(identity.pwd, "getpwnam", side_effect=KeyError), mock.patch.object(identity.grp, "getgrnam", side_effect=KeyError):
            with self.assertRaisesRegex(identity.IdentityError,"supplementary membership"):
                identity._HostStore.check_choice(None,chosen)

    def local_nss(self):
        return (Path(__file__).parent/"authselect-local-files.nsswitch").read_bytes()

    @contextmanager
    def mocked_nss(self, effective=None):
        with ExitStack() as stack:
            for module, name in ((identity.pwd,"getpwall"),(identity.grp,"getgrall")):
                stack.enter_context(mock.patch.object(module,name,return_value=[]))
            for module, name in ((identity.pwd,"getpwuid"),(identity.pwd,"getpwnam"),
                                 (identity.grp,"getgrgid"),(identity.grp,"getgrnam")):
                stack.enter_context(mock.patch.object(module,name,side_effect=KeyError))
            lookup=stack.enter_context(mock.patch.object(identity.os,"getgrouplist",
                side_effect=effective or (lambda name,gid: [gid])))
            yield lookup

    def refuse_nss_before_mutation(self, policy, needle):
        self.write("etc/nsswitch.conf",policy)
        before=self.raw()
        with self.mocked_nss(), self.assertRaisesRegex(identity.IdentityError,needle):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(self.raw(),before)
        self.assertFalse((self.root/identity.METADATA).exists())

    def test_verbatim_local_nss_profile_and_pre_post_creation_membership(self):
        self.write("etc/nsswitch.conf",self.local_nss())
        observed=[]
        def membership(name,gid):
            self.assertEqual(name,identity.NAME)
            observed.append(identity.NAME in identity.read_validate(self.raw()).passwd)
            return [gid]
        with self.mocked_nss(membership):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(observed,[False,True])

    def test_positive_fixture_matches_measured_authselect_template_without_altfiles(self):
        template=(Path(__file__).parent/"authselect-local-template.nsswitch").read_bytes()
        rendered=template.replace(b'{if "with-altfiles":altfiles }',b'').replace(
            b'{if "with-altfiles":altfiles [SUCCESS=merge] }',b'')
        fixture=b"\n".join(line for line in self.local_nss().splitlines() if not line.startswith(b"#"))+b"\n"
        self.assertEqual(rendered,fixture)
        identity._nss_policy(rendered)

    def test_subid_files_or_documented_absence_and_safe_initgroups(self):
        policy=self.local_nss()
        for suffix in (b"",b"subid: files\n",b"initgroups: files\n",b"initgroups: systemd\n",
                       b"subid: files\ninitgroups: files systemd\n"):
            with self.subTest(suffix=suffix):
                identity._nss_policy(policy+suffix)

    def test_nonfiles_subid_refuses_before_mutation(self):
        for line in (b"subid: sss\n",b"subid: ldap\n",b"subid: files systemd\n",
                     b"subid: files files\n",b"subid: files [SUCCESS=merge]\n",b"subid:\n"):
            with self.subTest(line=line):
                self.refuse_nss_before_mutation(self.local_nss()+line,"subid")

    def test_initgroups_remote_or_unknown_actions_refuse_before_mutation(self):
        for line in (b"initgroups: sss\n",b"initgroups: ldap\n",b"initgroups: files files\n",
                     b"initgroups: files [SUCCESS=merge] systemd\n",b"initgroups:\n"):
            with self.subTest(line=line):
                self.refuse_nss_before_mutation(self.local_nss()+line,"initgroups")

    def test_initgroups_subset_uses_actual_configured_group_sources(self):
        policy=self.local_nss().replace(b"group:      files [SUCCESS=merge] systemd",b"group: files")
        self.refuse_nss_before_mutation(policy+b"initgroups: systemd\n","configured group sources")

    def test_nss_duplicates_casing_and_whitespace_variants_do_not_bypass(self):
        for line in (b"subid: files\nsubid: sss\n",b"subid: files\nSUBID: sss\n",
                     b"SUBID: sss\n",b"subid : sss\n",b"initgroups : sss\n",
                     b"initgroups: files\ninitgroups: files\n",b"subid files\n",
                     b"gshadow: files\n"):
            with self.subTest(line=line):
                self.refuse_nss_before_mutation(self.local_nss()+line,"NSS")

    def test_only_exact_group_merge_action_and_position_are_accepted(self):
        policy=self.local_nss()
        for value in (b"files [SUCCESS=return] systemd",b"[SUCCESS=merge] files systemd",
                      b"files systemd [SUCCESS=merge]",b"files [success=merge] systemd",
                      b"files [SUCCESS=merge] files",b"files [SUCCESS=merge] sss"):
            with self.subTest(value=value):
                self.refuse_nss_before_mutation(policy.replace(b"files [SUCCESS=merge] systemd",value),"group")
        self.refuse_nss_before_mutation(policy.replace(b"shadow:     files systemd",
            b"shadow: files [SUCCESS=merge] systemd"),"shadow")

    def test_pinned_base_altfiles_is_explicit_refusal(self):
        measured=(Path(__file__).parent/"pinned-base-effective.nsswitch").read_bytes()
        self.refuse_nss_before_mutation(measured,"altfiles.*usr/lib/passwd.*usr/lib/group")

    def test_altfiles_is_refused_in_each_guarded_database(self):
        for key in (b"passwd",b"group",b"shadow",b"gshadow",b"subid",b"initgroups"):
            with self.subTest(key=key):
                policy=b"\n".join(line for line in self.local_nss().splitlines()
                                  if not line.startswith(key+b":"))+b"\n"+key+b": files altfiles\n"
                self.refuse_nss_before_mutation(policy,"altfiles")

    def test_effective_membership_hidden_from_enumeration_refuses_before_writes(self):
        self.write("etc/nsswitch.conf",self.local_nss())
        before=self.raw()
        class NoWrites(NSSFixtureStore):
            def replace(inner,*args):
                self.fail("effective group refusal must precede every replace")
        with self.mocked_nss(lambda name,gid: [gid,10]), self.assertRaisesRegex(
                identity.IdentityError,"effective supplementary membership"):
            self.run_provision(NoWrites)
        self.assertEqual(self.raw(),before)
        self.assertFalse((self.root/identity.METADATA).exists())

    def test_effective_membership_lookup_error_refuses_before_writes(self):
        self.write("etc/nsswitch.conf",self.local_nss())
        before=self.raw()
        def failure(name,gid):
            raise OSError(errno.EIO,"fixture NSS unavailable")
        with self.mocked_nss(failure), self.assertRaisesRegex(identity.IdentityError,"effective membership lookup failed"):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(self.raw(),before)
        self.assertFalse((self.root/identity.METADATA).exists())

    def test_post_creation_membership_failure_never_commits_identity(self):
        self.write("etc/nsswitch.conf",self.local_nss())
        def membership(name,gid):
            exists=identity.NAME in identity.read_validate(self.raw()).passwd
            return [gid,10] if exists else [gid]
        with self.mocked_nss(membership), self.assertRaisesRegex(identity.IdentityError,"effective supplementary membership"):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(json.loads((self.root/identity.METADATA).read_text())["phase"],"prepared")
        before=self.raw()
        with self.mocked_nss(lambda name,gid: [gid,10]), self.assertRaises(identity.IdentityError):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(self.raw(),before)
        with self.mocked_nss():
            self.run_provision(NSSFixtureStore)
        self.assertEqual(json.loads((self.root/identity.METADATA).read_text())["phase"],"committed")

    def test_committed_identity_effective_membership_drift_refuses_without_writes(self):
        self.write("etc/nsswitch.conf",self.local_nss())
        with self.mocked_nss():
            self.run_provision(NSSFixtureStore)
        before=self.raw()
        record=(self.root/identity.METADATA).read_bytes()
        with self.mocked_nss(lambda name,gid: [gid,10]), self.assertRaises(identity.IdentityError):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(self.raw(),before)
        self.assertEqual((self.root/identity.METADATA).read_bytes(),record)

    def test_nsswitch_read_errors_name_fixed_policy_path(self):
        from types import SimpleNamespace
        for failure in (OSError(errno.ELOOP,"symlink fixture"),OSError(errno.EACCES,"denied fixture")):
            with self.subTest(errno=failure.errno):
                store=SimpleNamespace(read=mock.Mock(side_effect=failure))
                with self.assertRaisesRegex(identity.IdentityError,"etc/nsswitch.conf.*authselect symlinks"):
                    identity._HostStore.check_sources(store)
                store.read.assert_called_once_with("etc/nsswitch.conf")

    def test_authselect_symlink_remains_incompatible_and_cannot_escape_fixture(self):
        self.write("etc/authselect/nsswitch.conf",self.local_nss())
        (self.root/"etc/nsswitch.conf").symlink_to("authselect/nsswitch.conf")
        before=self.raw()
        with self.mocked_nss(), self.assertRaisesRegex(identity.IdentityError,"etc/nsswitch.conf.*symlinks"):
            self.run_provision(NSSFixtureStore)
        self.assertEqual(self.raw(),before)
        self.assertFalse((self.root/identity.METADATA).exists())

    def test_library_has_no_cli_process_or_service_execution(self):
        text=(ROOT/"management-lifecycle/identity.py").read_text()
        import ast
        tree=ast.parse(text)
        self.assertFalse(any(isinstance(n,(ast.Import,ast.ImportFrom)) and
                             any(alias.name in ("subprocess","argparse") for alias in n.names)
                             for n in ast.walk(tree)))
        self.assertNotIn('if __name__ ==',text)


if __name__ == "__main__":
    unittest.main()
