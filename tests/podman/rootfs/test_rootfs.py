"""Offline adversarial fixtures; no Podman, installed labels, or KVM proof.

The materialization tests run as uid 0 inside a disposable rootless Linux
container. They never target the installed /usr management-rootfs path.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load_tool(name):
    loader = importlib.machinery.SourceFileLoader(name.replace('-', '_'), str(ROOT / 'tools' / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


@unittest.skipUnless(sys.platform.startswith('linux'), 'requires Linux source fd/mount APIs')
class SourceOracleFixture(unittest.TestCase):
    def test_reviewed_source_has_explicit_golden_identity_without_materialization(self):
        builder = load_tool('build-management-rootfs')
        reviewed = json.loads((Path(__file__).with_name('expected-source-identity.json')).read_bytes())
        with mock.patch.object(builder.tempfile, 'mkdtemp', side_effect=AssertionError('must not create a tree')):
            expected = builder.expected_manifest(builder.source_snapshot(builder.SOURCE_ROOT))
        self.assertEqual(reviewed, {
            'build_id': expected['build_id'],
            'manifest_sha256': hashlib.sha256(builder.canonical(expected)).hexdigest(),
        })


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'requires disposable rootless Linux container uid 0; no installed-image proof')
class RootfsFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_tool('build-management-rootfs')
        cls.verifier = load_tool('verify-management-rootfs')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sl-rootfs-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bundle = self.base / 'bundle'
        self.builder.build_bundle(self.bundle)
        self.rootfs = self.bundle / 'rootfs'
        self.manifest_path = self.bundle / 'manifest.json'
        self.manifest_bytes = self.manifest_path.read_bytes()
        self.manifest = json.loads(self.manifest_bytes)
        self.digest = hashlib.sha256(self.manifest_bytes).hexdigest()

    def verify(self, bundle=None, digest=None):
        return self.verifier.verify_bundle(bundle or self.bundle, self.digest if digest is None else digest)

    def fail_verify(self, bundle=None, digest=None):
        with self.assertRaises(self.verifier.VerificationError):
            self.verify(bundle, digest)

    def entries(self, kind):
        return [entry for entry in self.manifest['entries'] if entry['type'] == kind]

    def regular(self):
        return self.rootfs / self.entries('file')[0]['path']

    def directory(self):
        return next(self.rootfs / entry['path'] for entry in self.entries('directory')
                    if entry['path'] not in ('', '.'))

    def write_manifest(self, manifest):
        data = (json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
        self.manifest_path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def test_roundtrip_is_offline_only(self):
        result = self.verify()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['scope'], 'offline-source-fixture')
        self.assertEqual(result['selinux'], 'UNPROVEN')
        self.assertEqual(result['runtime'], 'UNPROVEN')

    def test_two_builds_different_umasks_have_identical_oracle(self):
        other = self.base / 'other'
        previous = os.umask(0o002)
        try:
            self.builder.build_bundle(other)
        finally:
            os.umask(previous)
        self.assertEqual(self.manifest_bytes, (other / 'manifest.json').read_bytes())
        self.verify(other)

    def builder_cli(self, output):
        return subprocess.run(
            [sys.executable, str(ROOT / 'tools' / 'build-management-rootfs'),
             '--offline-output', str(output)],
            capture_output=True, text=True, timeout=30, check=False)

    def test_clean_parent_cli_publishes_verified_bundle(self):
        parent = self.base / 'clean-parent'
        parent.mkdir(mode=0o700)
        output = parent / 'bundle'
        result = self.builder_cli(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response['status'], 'PASS')
        self.assertEqual(response['manifest_sha256'], self.digest)
        self.verify(output)

    def test_real_default_acl_cli_refuses_publication(self):
        setfacl, getfacl = shutil.which('setfacl'), shutil.which('getfacl')
        self.assertIsNotNone(setfacl, 'real default-ACL regression requires existing setfacl; gate is not skipped')
        self.assertIsNotNone(getfacl, 'real default-ACL regression requires existing getfacl; gate is not skipped')
        parent = self.base / 'acl-parent'
        parent.mkdir(mode=0o700)
        acl = subprocess.run([setfacl, '-d', '-m', 'u:nobody:rwx', str(parent)],
                             capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(acl.returncode, 0, acl.stderr)
        observed = subprocess.run([getfacl, '-cp', str(parent)],
                                  capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertIn('default:user:nobody:rwx', observed.stdout)
        self.assertEqual(parent.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
        output = parent / 'bundle'
        result = self.builder_cli(output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('PASS', result.stdout + result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(list(parent.glob('.sl-rootfs-*')), [])

    def test_external_verifier_receives_source_oracle_before_publish(self):
        output = self.base / 'independently-verified'
        real_run, real_publish = subprocess.run, self.builder.publish
        reviewed = json.loads(Path(__file__).with_name('expected-source-identity.json').read_bytes())
        events = []
        def verified(command, **kwargs):
            events.append('verify')
            self.assertEqual(command[:3], [sys.executable, '-I', '-B'])
            self.assertEqual(Path(command[3]), ROOT / 'tools' / 'verify-management-rootfs')
            self.assertEqual(command[4], '--offline-bundle')
            stage = Path(command[5])
            self.assertEqual(stage.parent, output.parent)
            self.assertTrue(stage.name.startswith('.sl-rootfs-'))
            self.assertEqual(command[6:], ['--expected-manifest-sha256', reviewed['manifest_sha256']])
            self.assertEqual(kwargs.get('timeout'), 30)
            self.assertFalse(kwargs.get('shell', False))
            self.assertFalse(output.exists())
            return real_run(command, **kwargs)
        def published(stage, destination):
            events.append('publish')
            self.assertEqual(events, ['verify', 'publish'])
            return real_publish(stage, destination)
        with mock.patch.object(self.builder.subprocess, 'run', side_effect=verified):
            with mock.patch.object(self.builder, 'publish', side_effect=published):
                self.builder.build_bundle(output)
        self.assertEqual(events, ['verify', 'publish'])
        self.verify(output)

    def test_external_verifier_refusal_never_publishes(self):
        output = self.base / 'verifier-refused'
        refusal = subprocess.CompletedProcess([], 1, stdout='', stderr='injected verifier refusal')
        with mock.patch.object(self.builder.subprocess, 'run', return_value=refusal):
            with mock.patch.object(self.builder, 'publish') as publish:
                with self.assertRaises(self.builder.BuildError):
                    self.builder.build_bundle(output)
        publish.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob('.sl-rootfs-*')), [])

    def test_unexpected_external_verifier_response_never_publishes(self):
        good = dict(status='PASS', scope='offline-source-fixture', selinux='UNPROVEN',
                    runtime='UNPROVEN', build_id=self.manifest['build_id'])
        responses = [
            ('', ''),
            ('{"status":', ''),
            ('{"status":"PASS","status":"PASS"}', ''),
            (json.dumps(dict(good, build_id='0' * 64)), ''),
            (json.dumps(dict(good, scope='installed')), ''),
            (json.dumps(dict(good, unexpected='extra')), ''),
            (json.dumps(good), 'unexpected stderr'),
        ]
        for stdout, stderr in responses:
            with self.subTest(stdout=stdout, stderr=stderr):
                output = self.base / 'malformed-verifier'
                response = subprocess.CompletedProcess([], 0, stdout=stdout, stderr=stderr)
                with mock.patch.object(self.builder.subprocess, 'run', return_value=response):
                    with mock.patch.object(self.builder, 'publish') as publish:
                        with self.assertRaises(self.builder.BuildError):
                            self.builder.build_bundle(output)
                publish.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(list(self.base.glob('.sl-rootfs-*')), [])

    def test_unavailable_or_timed_out_external_verifier_never_publishes(self):
        for error in (FileNotFoundError('verifier absent'), subprocess.TimeoutExpired([], 30)):
            with self.subTest(error=type(error).__name__):
                output = self.base / 'unavailable-verifier'
                with mock.patch.object(self.builder.subprocess, 'run', side_effect=error):
                    with mock.patch.object(self.builder, 'publish') as publish:
                        with self.assertRaises(self.builder.BuildError):
                            self.builder.build_bundle(output)
                publish.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(list(self.base.glob('.sl-rootfs-*')), [])

    def test_changed_file_bytes_fail(self):
        self.regular().write_bytes(b'hostile replacement\n')
        self.fail_verify()

    def test_extra_file_fails(self):
        (self.rootfs / 'extra').write_text('unlisted')
        self.fail_verify()

    def test_extra_loader_or_library_fails(self):
        (self.rootfs / 'lib').mkdir(exist_ok=True)
        (self.rootfs / 'lib' / 'ld-hostile.so').write_bytes(b'not authorized')
        self.fail_verify()

    def test_deleted_file_fails(self):
        self.regular().unlink()
        self.fail_verify()

    def test_renamed_file_fails(self):
        path = self.regular()
        path.rename(path.with_name(path.name + '-renamed'))
        self.fail_verify()

    def test_extra_empty_directory_fails(self):
        (self.rootfs / 'unlisted-empty').mkdir()
        self.fail_verify()

    def test_renamed_directory_fails(self):
        path = self.directory()
        path.rename(path.with_name(path.name + '-renamed'))
        self.fail_verify()

    def test_file_to_directory_swap_fails(self):
        path = self.regular()
        path.unlink()
        path.mkdir()
        self.fail_verify()

    def test_file_mode_drift_fails(self):
        path = self.regular()
        path.chmod(stat.S_IMODE(path.stat().st_mode) ^ 0o100)
        self.fail_verify()

    def test_world_writable_file_fails(self):
        self.regular().chmod(0o666)
        self.fail_verify()

    def test_writable_directory_fails(self):
        self.directory().chmod(0o777)
        self.fail_verify()

    def test_setuid_fails(self):
        self.regular().chmod(0o4755)
        self.assertTrue(self.regular().stat().st_mode & stat.S_ISUID)
        self.fail_verify()

    def test_setgid_fails(self):
        self.regular().chmod(0o2755)
        self.assertTrue(self.regular().stat().st_mode & stat.S_ISGID)
        self.fail_verify()

    def test_owner_drift_fails(self):
        os.chown(self.regular(), 1, 0)
        self.fail_verify()

    def test_group_drift_fails(self):
        os.chown(self.regular(), 0, 1)
        self.fail_verify()

    def test_rootfs_owner_drift_fails(self):
        os.chown(self.rootfs, 1, 0)
        self.fail_verify()

    def test_fifo_fails(self):
        os.mkfifo(self.rootfs / 'hostile-fifo')
        self.fail_verify()

    def test_unix_socket_fails(self):
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(self.rootfs / 'hostile-socket'))
            self.fail_verify()

    def test_extra_xattr_fails(self):
        os.setxattr(self.regular(), 'user.unreviewed', b'hostile')
        self.fail_verify()

    def test_bundle_extra_entry_fails(self):
        (self.bundle / 'unexpected').write_bytes(b'extra')
        self.fail_verify()

    def test_rootfs_symlink_fails(self):
        original = self.base / 'detached-rootfs'
        self.rootfs.rename(original)
        self.rootfs.symlink_to(original, target_is_directory=True)
        self.fail_verify()

    def test_bundle_symlink_fails(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.bundle, target_is_directory=True)
        self.fail_verify(alias)

    def test_bundle_symlink_ancestor_fails(self):
        alias = self.base / 'alias-parent'
        alias.symlink_to(self.base, target_is_directory=True)
        self.fail_verify(alias / 'bundle')

    def test_file_symlink_to_outside_fails(self):
        path = self.regular()
        outside = self.base / 'outside'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        self.fail_verify()

    def test_dangling_symlink_fails(self):
        (self.rootfs / 'bad-link').symlink_to('missing')
        self.fail_verify()

    def test_extra_outside_hardlink_fails(self):
        os.link(self.regular(), self.base / 'external-alias')
        self.fail_verify()

    def test_missing_trusted_oracle_fails(self):
        for digest in ('', '0' * 64, 'not-a-sha256'):
            with self.subTest(digest=digest):
                self.fail_verify(digest=digest)

    def test_manifest_modified_without_oracle_change_fails(self):
        self.manifest_path.write_bytes(self.manifest_bytes + b' ')
        self.fail_verify()

    def test_truncated_manifest_fails(self):
        data = self.manifest_bytes[:len(self.manifest_bytes) // 2]
        self.manifest_path.write_bytes(data)
        self.fail_verify(digest=hashlib.sha256(data).hexdigest())

    def test_duplicate_json_key_fails_even_with_matching_digest(self):
        data = b'{"schema":1,"schema":1}\n'
        self.manifest_path.write_bytes(data)
        self.fail_verify(digest=hashlib.sha256(data).hexdigest())

    def test_manifest_symlink_fails(self):
        saved = self.base / 'saved-manifest'
        self.manifest_path.rename(saved)
        self.manifest_path.symlink_to(saved)
        self.fail_verify()

    def test_unsupported_manifest_version_fails(self):
        self.manifest['schema'] = 999
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_duplicate_manifest_path_fails(self):
        self.manifest['entries'].append(dict(self.manifest['entries'][0]))
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_invalid_manifest_paths_fail(self):
        for path in ('/etc/hostile', '../escape', 'etc/../escape', 'etc//duplicate', 'etc/./file',
                     'etc/cafe\u0301', 'etc/\x00bad'):
            with self.subTest(path=path):
                candidate = json.loads(self.manifest_bytes)
                candidate['entries'][0]['path'] = path
                self.fail_verify(digest=self.write_manifest(candidate))

    def test_manifest_owner_claim_cannot_authorize_nonroot(self):
        self.manifest['entries'][0]['uid'] = 1
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_manifest_label_expectation_drift_fails(self):
        entry = self.manifest['entries'][0]
        key = next((name for name in entry if 'selinux' in name), 'selinux')
        entry[key] = 'unconfined_u:object_r:unconfined_t:s0'
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_manifest_file_capability_claim_fails(self):
        self.manifest['entries'][0]['file_capabilities'] = 'cap_sys_admin=ep'
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_manifest_extra_untrusted_field_fails(self):
        self.manifest['caller_entrypoint'] = '/bin/hostile'
        self.fail_verify(digest=self.write_manifest(self.manifest))

    def test_intended_hardlink_equivalence_passes(self):
        alias = next(entry for entry in self.entries('file') if entry['hardlink_to'] is not None)
        original = self.rootfs / alias['hardlink_to']
        linked = self.rootfs / alias['path']
        self.assertEqual(original.stat().st_ino, linked.stat().st_ino)
        self.verify()

    def test_broken_intended_hardlink_fails(self):
        alias = next(entry for entry in self.entries('file') if entry['hardlink_to'] is not None)
        path = self.rootfs / alias['path']
        contents, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
        path.unlink()
        path.write_bytes(contents)
        path.chmod(mode)
        self.fail_verify()

    def test_unintended_in_tree_hardlink_fails(self):
        path = self.regular()
        os.link(path, self.rootfs / 'unlisted-alias')
        self.fail_verify()

    def test_mount_substitution_fails_closed_without_mount_privilege(self):
        original = self.verifier._mount_id
        calls = 0
        def changed_mount(fd):
            nonlocal calls
            calls += 1
            return original(fd) + (1 if calls > 1 else 0)
        with mock.patch.object(self.verifier, '_mount_id', side_effect=changed_mount):
            self.fail_verify()

    def test_observed_file_race_fails_closed(self):
        original = self.verifier._file_digest
        changed = False
        def mutate_while_reading(fd):
            nonlocal changed
            result = original(fd)
            if not changed:
                changed = True
                self.regular().write_bytes(b'changed during scan')
            return result
        with mock.patch.object(self.verifier, '_file_digest', side_effect=mutate_while_reading):
            self.fail_verify()
        self.assertTrue(changed)

    def test_capability_xattr_rejected_simulated_without_host_capability(self):
        # Injection models kernel xattr reporting, not installed SELinux proof.
        original = self.verifier.os.listxattr
        def with_capability(path, *args, **kwargs):
            return list(original(path, *args, **kwargs)) + ['security.capability']
        with mock.patch.object(self.verifier.os, 'listxattr', side_effect=with_capability):
            self.fail_verify()

    def copy_source(self):
        target = self.base / 'source'
        shutil.copytree(self.builder.SOURCE_ROOT, target)
        return target

    def fail_build_source(self, source):
        output = self.base / 'hostile-output'
        with mock.patch.object(self.builder, 'SOURCE_ROOT', source):
            with self.assertRaises((self.builder.BuildError, OSError)):
                self.builder.build_bundle(output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob('.sl-rootfs-*')), [])

    def test_unlisted_source_input_rejected(self):
        source = self.copy_source()
        (source / 'unlisted').write_bytes(b'unreviewed')
        self.fail_build_source(source)

    def test_unlisted_empty_source_directory_rejected(self):
        source = self.copy_source()
        (source / 'unlisted-empty').mkdir()
        self.fail_build_source(source)

    def test_source_directory_xattr_rejected(self):
        source = self.copy_source()
        os.setxattr(source / 'inputs', 'user.hostile', b'x')
        self.fail_build_source(source)

    def test_pinned_source_byte_change_rejected(self):
        source = self.copy_source()
        (source / 'inputs' / 'message.txt').write_bytes(b'replacement')
        self.fail_build_source(source)

    def test_deleted_pinned_source_rejected(self):
        source = self.copy_source()
        (source / 'inputs' / 'message.txt').unlink()
        self.fail_build_source(source)

    def test_source_symlink_rejected(self):
        source = self.copy_source()
        victim = source / 'inputs' / 'message.txt'
        copied = self.base / 'same-source-bytes'
        copied.write_bytes(victim.read_bytes())
        victim.unlink()
        victim.symlink_to(copied)
        self.fail_build_source(source)

    def test_source_ancestor_symlink_rejected(self):
        source = self.copy_source()
        alias = self.base / 'source-alias'
        alias.symlink_to(source, target_is_directory=True)
        self.fail_build_source(alias)

    def test_source_hardlink_rejected(self):
        source = self.copy_source()
        os.link(source / 'inputs' / 'message.txt', self.base / 'source-alias')
        self.fail_build_source(source)

    def test_source_fifo_rejected(self):
        source = self.copy_source()
        os.mkfifo(source / 'hostile-fifo')
        self.fail_build_source(source)

    def test_source_xattr_rejected(self):
        source = self.copy_source()
        os.setxattr(source / 'inputs' / 'message.txt', 'user.hostile', b'x')
        self.fail_build_source(source)

    def test_source_special_mode_rejected(self):
        source = self.copy_source()
        (source / 'inputs' / 'message.txt').chmod(0o4644)
        self.fail_build_source(source)

    def test_source_mount_boundary_rejected_simulated(self):
        source = self.copy_source()
        original = self.builder.mount_id
        calls = 0
        def changed_mount(fd):
            nonlocal calls
            calls += 1
            return original(fd) + (1 if calls > 1 else 0)
        with mock.patch.object(self.builder, 'mount_id', side_effect=changed_mount):
            self.fail_build_source(source)

    def test_source_change_between_snapshots_rejected(self):
        source = self.copy_source()
        original = self.builder.source_snapshot
        calls = 0
        def changed_snapshot(root):
            nonlocal calls
            result = original(root)
            calls += 1
            if calls == 2:
                result['inputs/message.txt'] += b'changed'
            return result
        with mock.patch.object(self.builder, 'source_snapshot', side_effect=changed_snapshot):
            self.fail_build_source(source)
        self.assertEqual(calls, 2)

    def test_interrupted_publish_leaves_no_accepted_bundle(self):
        output = self.base / 'interrupted'
        with mock.patch.object(self.builder, 'publish', side_effect=InterruptedError('injected interruption')):
            with self.assertRaises(InterruptedError):
                self.builder.build_bundle(output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob('.sl-rootfs-*')), [])
        self.verify()

    def test_recipe_bad_paths_rejected(self):
        original = json.loads((self.builder.SOURCE_ROOT / 'rootfs-spec.json').read_text())
        for path in ('/absolute', '../escape', 'etc/../escape', 'etc//file', 'etc/./file', 'etc/cafe\u0301'):
            with self.subTest(path=path):
                recipe = json.loads(json.dumps(original))
                recipe['entries'][0]['path'] = path
                snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
                snapshot['rootfs-spec.json'] = self.builder.canonical(recipe)
                with self.assertRaises(self.builder.BuildError):
                    self.builder.expected_manifest(snapshot)

    def test_recipe_lone_surrogate_path_has_controlled_build_error(self):
        snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        recipe = json.loads(snapshot['rootfs-spec.json'])
        recipe['entries'][0]['path'] = 'etc/\ud800'
        # JSON permits this escape; strict UTF-8 filesystem paths do not.
        snapshot['rootfs-spec.json'] = json.dumps(recipe, ensure_ascii=True).encode()
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot)

    def test_recipe_duplicate_paths_rejected(self):
        snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        recipe = json.loads(snapshot['rootfs-spec.json'])
        recipe['entries'].append(dict(recipe['entries'][0]))
        snapshot['rootfs-spec.json'] = self.builder.canonical(recipe)
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot)

    def test_recipe_escaping_and_dangling_links_rejected(self):
        for target in ('../../../outside', '/etc/passwd', 'unlisted-missing'):
            with self.subTest(target=target):
                snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
                recipe = json.loads(snapshot['rootfs-spec.json'])
                next(entry for entry in recipe['entries'] if entry['path'] == 'etc/mtab')['target'] = target
                snapshot['rootfs-spec.json'] = self.builder.canonical(recipe)
                with self.assertRaises(self.builder.BuildError):
                    self.builder.expected_manifest(snapshot)

    def test_recipe_extra_dynamic_mount_exclusion_rejected(self):
        snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        recipe = json.loads(snapshot['rootfs-spec.json'])
        recipe['dynamic_mounts'] = ['/usr/bin']
        snapshot['rootfs-spec.json'] = self.builder.canonical(recipe)
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot)

    def test_recipe_unsupported_objects_rejected(self):
        for kind in ('block', 'character', 'socket', 'fifo'):
            with self.subTest(kind=kind):
                snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
                recipe = json.loads(snapshot['rootfs-spec.json'])
                recipe['entries'][0]['type'] = kind
                snapshot['rootfs-spec.json'] = self.builder.canonical(recipe)
                with self.assertRaises(self.builder.BuildError):
                    self.builder.expected_manifest(snapshot)

    def test_recipe_missing_source_oracle_rejected(self):
        snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        del snapshot['rootfs-spec.json']
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot)

    def test_recipe_duplicate_json_keys_rejected(self):
        snapshot = self.builder.source_snapshot(self.builder.SOURCE_ROOT)
        snapshot['rootfs-spec.json'] = b'{"schema":1,"schema":1}'
        with self.assertRaises(self.builder.BuildError):
            self.builder.expected_manifest(snapshot)

    def test_no_partial_publish_when_destination_exists(self):
        before = self.manifest_path.read_bytes()
        with self.assertRaises(Exception):
            self.builder.build_bundle(self.bundle)
        self.assertEqual(self.manifest_path.read_bytes(), before)
        self.verify()


if __name__ == '__main__':
    unittest.main()
