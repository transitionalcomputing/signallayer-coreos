"""L1 real-filesystem and injected-observation controls. Never execute ELF.

Run ONLY in the approved disposable rootless Linux uid0 container with a
private /run tmpfs, no network or writable host shares. Root-driven swaps are
fault injections, not claims that hostile root can be excluded.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_rootfs import fixture_checkout, load_tool, synthetic_elf


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'requires isolated Linux uid0 and private /run')
class CheckerStagingTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_tool('build-management-rootfs')
        self.temp = tempfile.TemporaryDirectory(prefix='sl-l1-tests-', dir='/run')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.parent = self.base / 'parent'
        self.parent.mkdir(mode=0o700)
        self.builder.CHECKER_STAGING_PARENT = self.parent

    def assert_empty(self):
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_positive_private_bytes_modes_and_cleanup(self):
        with self.builder.private_checker_files(b'captured', b'parser') as (path, validate):
            self.assertEqual(path.parent, self.parent)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for leaf, payload in (('artifact', b'captured'), ('verify-static-fixture', b'parser')):
                self.assertEqual((path / leaf).read_bytes(), payload)
                self.assertEqual(stat.S_IMODE((path / leaf).stat().st_mode), 0o400)
            validate()
        self.assert_empty()

    def test_poisoned_environment_and_cached_tempdir_cannot_select_staging(self):
        poison = self.base / 'poison'
        poison.mkdir(mode=0o777)
        with mock.patch.dict(os.environ, {k: str(poison) for k in ('TMPDIR', 'TEMP', 'TMP')}), \
                mock.patch.object(tempfile, 'tempdir', str(poison)):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                self.assertEqual(path.parent, self.parent)
                validate()
        self.assertEqual(list(poison.iterdir()), [])
        self.assert_empty()

    def test_shared_sticky_ancestor_is_refused(self):
        self.base.chmod(0o1777)
        try:
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y'):
                    self.fail('shared ancestor accepted')
        finally:
            self.base.chmod(0o700)
        self.assert_empty()

    def test_nonroot_owner_is_refused(self):
        os.chown(self.parent, 1, 0)
        try:
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y'):
                    self.fail('nonroot owner accepted')
        finally:
            os.chown(self.parent, 0, 0)
        self.assert_empty()

    def test_symlink_parent_is_refused(self):
        link = self.base / 'link'
        link.symlink_to(self.parent)
        self.builder.CHECKER_STAGING_PARENT = link
        with self.assertRaises(OSError):
            with self.builder.private_checker_files(b'x', b'y'):
                self.fail('symlink accepted')
        self.assert_empty()

    def test_acl_observation_fails_closed(self):
        # Injected ACL observation; a real setfacl case is a separate native gate.
        with mock.patch.object(self.builder.os, 'listxattr', return_value=['system.posix_acl_access']):
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y'):
                    self.fail('ACL accepted')
        self.assert_empty()

    def test_real_extended_acl_is_refused(self):
        # Named user with zero effective permissions still constitutes an
        # unreviewed ACL. Do not skip an unsupported filesystem: that is a gate
        # failure requiring a supported isolated Linux test environment.
        entries = [(1, 7, 0xffffffff), (2, 0, 1), (4, 0, 0xffffffff),
                   (16, 0, 0xffffffff), (32, 0, 0xffffffff)]
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *e) for e in entries)
        os.setxattr(self.parent, 'system.posix_acl_access', acl)
        try:
            self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o700)
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y'):
                    self.fail('real ACL accepted')
        finally:
            os.removexattr(self.parent, 'system.posix_acl_access')
        self.assert_empty()

    def test_staged_hardlink_alias_is_refused(self):
        alias = self.base / 'alias'
        try:
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                    os.link(path / 'artifact', alias)
                    validate()
        finally:
            alias.unlink(missing_ok=True)
        self.assert_empty()

    def test_staged_leaf_replacement_is_detected_and_cleaned(self):
        with self.assertRaises(self.builder.BuildError):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                leaf = path / 'verify-static-fixture'
                leaf.unlink()
                leaf.write_bytes(b'z')
                leaf.chmod(0o400)
                validate()
        self.assert_empty()

    def test_staged_symlink_is_never_followed_or_cleaned_through(self):
        sentinel = self.base / 'sentinel'
        sentinel.write_bytes(b'preserve')
        with self.assertRaises(OSError):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                (path / 'artifact').unlink()
                (path / 'artifact').symlink_to(sentinel)
                validate()
        self.assertEqual(sentinel.read_bytes(), b'preserve')
        self.assert_empty()

    def test_changed_parent_mode_is_detected(self):
        try:
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                    self.parent.chmod(0o777)
                    validate()
        finally:
            self.parent.chmod(0o700)
        self.assert_empty()

    def test_parent_substitution_is_detected_without_touching_replacement(self):
        moved = self.base / 'original'
        with self.assertRaises(self.builder.BuildError):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                self.parent.rename(moved)
                self.parent.mkdir(mode=0o700)
                (self.parent / 'sentinel').write_bytes(b'preserve')
                validate()
        self.assertEqual((self.parent / 'sentinel').read_bytes(), b'preserve')
        self.assertEqual(list(moved.iterdir()), [])

    def test_child_substitution_is_detected_and_replacement_preserved(self):
        moved = self.base / 'moved-child'
        with self.assertRaises(self.builder.BuildError):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                path.rename(moved)
                path.mkdir(mode=0o700)
                (path / 'sentinel').write_bytes(b'preserve')
                validate()
        self.assertEqual((path / 'sentinel').read_bytes(), b'preserve')
        self.assertEqual(list(moved.iterdir()), [])
        # Hostile trusted-root relocation is outside guarantees. The original
        # directory can remain empty; no copied executable or artifact survives.

    def test_empty_child_replacement_is_preserved_by_cleanup_identity_guard(self):
        moved = self.base / 'empty-original'
        with self.assertRaises(self.builder.BuildError):
            with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                path.rename(moved)
                path.mkdir(mode=0o700)
                # Deliberately do not call validate here: this targets cleanup
                # after the post-yield check observes replacement.
        self.assertTrue(path.is_dir(), 'cleanup deleted the replacement directory')
        self.assertEqual(list(path.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_independent_parent_modes_are_refused_before_staging(self):
        for mode in (0o770, 0o707, 0o2700):
            with self.subTest(mode=oct(mode)):
                self.parent.chmod(mode)
                try:
                    with mock.patch.object(self.builder.os, 'mkdir', wraps=os.mkdir) as create:
                        with self.assertRaises(self.builder.BuildError):
                            with self.builder.private_checker_files(b'x', b'y'):
                                self.fail('unsafe initial mode accepted')
                        create.assert_not_called()
                finally:
                    self.parent.chmod(0o700)
                self.assert_empty()

    def test_higher_ancestor_owner_is_refused_before_staging(self):
        os.chown(self.base, 1, 0)
        try:
            with mock.patch.object(self.builder.os, 'mkdir', wraps=os.mkdir) as create:
                with self.assertRaises(self.builder.BuildError):
                    with self.builder.private_checker_files(b'x', b'y'):
                        self.fail('nonroot ancestor accepted')
                create.assert_not_called()
        finally:
            os.chown(self.base, 0, 0)
        self.assert_empty()

    def test_child_creation_mode_drift_is_refused(self):
        # Inject a creator that fails to honor 0700; validate real resulting
        # filesystem metadata. This is not an attacker privilege claim.
        mkdir = os.mkdir
        def wrong_mode(path, mode=0o777, *, dir_fd=None):
            return mkdir(path, 0o755, dir_fd=dir_fd)
        with mock.patch.object(self.builder.os, 'mkdir', side_effect=wrong_mode):
            with self.assertRaises(self.builder.BuildError):
                with self.builder.private_checker_files(b'x', b'y'):
                    self.fail('nonprivate child accepted')
        self.assert_empty()

    def test_unexpected_entry_validation_is_sensitive(self):
        with self.builder.private_checker_files(b'x', b'y') as (path, validate):
            extra = path / 'unexpected'
            extra.write_bytes(b'preserve until controlled test cleanup')
            observed = None
            try:
                validate()
            except self.builder.BuildError as error:
                observed = error
            finally:
                extra.unlink()
            self.assertIsInstance(observed, self.builder.BuildError)
            self.assertIn('unexpected checker staging entry', str(observed))
        self.assert_empty()

    def test_unlink_failure_is_not_successful_cleanup(self):
        unlink = os.unlink
        created = None
        def refused(leaf, *, dir_fd=None):
            if leaf == 'artifact':
                raise PermissionError(errno.EACCES, 'injected unlink failure')
            return unlink(leaf, dir_fd=dir_fd)
        try:
            with mock.patch.object(self.builder.os, 'unlink', side_effect=refused):
                with self.assertRaises(PermissionError):
                    with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                        created = path
            self.assertTrue((created / 'artifact').exists())
        finally:
            # Explicit fixture cleanup after the injected failure; production
            # cannot promise removal when the filesystem refuses unlink.
            if created is not None:
                for leaf in created.iterdir():
                    leaf.unlink()
                created.rmdir()
        self.assert_empty()

    def test_rmdir_failure_preserves_empty_private_directory_and_refuses(self):
        rmdir = os.rmdir
        created = None
        def refused(path, *, dir_fd=None):
            if str(path).startswith('.sl-w1-elf-'):
                raise PermissionError(errno.EACCES, 'injected rmdir failure')
            return rmdir(path, dir_fd=dir_fd)
        try:
            with mock.patch.object(self.builder.os, 'rmdir', side_effect=refused):
                with self.assertRaises(PermissionError):
                    with self.builder.private_checker_files(b'x', b'y') as (path, validate):
                        created = path
            self.assertTrue(created.is_dir())
            self.assertEqual(list(created.iterdir()), [])
        finally:
            if created is not None:
                created.rmdir()
        self.assert_empty()

    def test_exception_cleanup(self):
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            with self.builder.private_checker_files(b'x', b'y'):
                raise RuntimeError('injected')
        self.assert_empty()

    def test_concurrent_unprivileged_attempts_during_parser_validation(self):
        """Bounded real DAC attempts, not a hostile-root or exhaustive race proof.

        Only the forked worker drops identity, inside the approved disposable
        Linux namespace. Setup failures/errors are not counted as denials.
        """
        payload = synthetic_elf()
        checker = self.builder.STATIC_VERIFIER.read_bytes()
        expected_hash = hashlib.sha256(payload).hexdigest()
        for accessible in (False, True):
            with self.subTest(accessible_root_owned_ancestors=accessible):
                mode = 0o755 if accessible else 0o700
                self.base.chmod(mode)
                self.parent.chmod(mode)
                try:
                    with self.builder.private_checker_files(payload, checker) as (path, validate):
                        parent_socket, child_socket = socket.socketpair()
                        parent_socket.settimeout(5)
                        child_socket.settimeout(5)
                        pid = os.fork()
                        if pid == 0:
                            # The parent retains all staging fds; the attacker
                            # must not inherit that already-authorized access.
                            try:
                                parent_socket.close()
                                keep = child_socket.fileno()
                                for entry in os.listdir('/proc/self/fd'):
                                    fd = int(entry)
                                    if fd > 2 and fd != keep:
                                        try:
                                            os.close(fd)
                                        except OSError as error:
                                            if error.errno != errno.EBADF:
                                                raise
                                os.setgroups([])
                                os.setresgid(1, 1, 1)
                                os.setresuid(1, 1, 1)
                                status = dict(line.split(':', 1) for line in
                                              Path('/proc/self/status').read_text().splitlines()
                                              if ':' in line)
                                creds = {'uids': list(os.getresuid()),
                                         'gids': list(os.getresgid()), 'groups': os.getgroups(),
                                         'caps': {key: int(status[key].strip(), 16)
                                                  for key in ('CapEff', 'CapPrm', 'CapAmb')}}
                                if (creds['uids'] != [1, 1, 1] or creds['gids'] != [1, 1, 1]
                                        or creds['groups'] or any(creds['caps'].values())):
                                    raise RuntimeError('attacker credentials/capabilities not restricted')
                                remaining = []
                                for entry in os.listdir('/proc/self/fd'):
                                    fd = int(entry)
                                    try:
                                        os.fstat(fd)
                                    except OSError as error:
                                        if error.errno == errno.EBADF:
                                            continue
                                        raise
                                    if fd > 2:
                                        remaining.append(fd)
                                if remaining != [keep]:
                                    raise RuntimeError('inherited descriptor survived')
                                # The second case proves accessible ancestors;
                                # denial cannot be attributed only to base 0700.
                                if accessible:
                                    if path.name not in os.listdir(self.parent):
                                        raise RuntimeError('accessible ancestor positive control failed')
                                    for ancestor in (Path('/run'), self.base, self.parent):
                                        if not os.access(ancestor, os.R_OK | os.X_OK):
                                            raise RuntimeError('ancestor access positive control failed')
                                child_socket.sendall((json.dumps({'ready': creds,
                                    'remaining_fds': remaining, 'accessible': accessible}) + '\n').encode())
                                for round_number in range(32):
                                    if child_socket.recv(1) != b'G':
                                        raise RuntimeError('barrier missing')
                                    denials = {}
                                    attempts = {
                                        'read_capture': lambda: os.open(path / 'artifact', os.O_RDONLY),
                                        'write_checker': lambda: os.open(path / 'verify-static-fixture', os.O_WRONLY),
                                        'create_child': lambda: os.open(path / 'injected', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                                        'rename_child': lambda: os.rename(path, self.parent / 'attacker-renamed'),
                                        'symlink_parent': lambda: os.symlink('/dev/null', self.parent / 'attacker-link'),
                                    }
                                    for name, attempt in attempts.items():
                                        try:
                                            opened = attempt()
                                        except OSError as error:
                                            if error.errno not in (errno.EACCES, errno.EPERM):
                                                raise RuntimeError(f'{name}: unexpected errno {error.errno}') from error
                                            denials[name] = error.errno
                                        else:
                                            if isinstance(opened, int):
                                                os.close(opened)
                                            raise RuntimeError(name + ': unauthorized operation succeeded')
                                    child_socket.sendall((json.dumps({'round': round_number,
                                                                    'denials': denials}) + '\n').encode())
                                child_socket.close()
                                os._exit(0)
                            except BaseException as error:
                                try:
                                    child_socket.sendall((json.dumps({'error': repr(error)}) + '\n').encode())
                                except BaseException:
                                    pass
                                os._exit(1)
                        child_socket.close()
                        reader = parent_socket.makefile('rb')
                        reaped = False
                        try:
                            def receive():
                                line = reader.readline(8193)
                                self.assertTrue(line.endswith(b'\n') and len(line) <= 8192,
                                                'missing or unbounded worker report')
                                report = json.loads(line)
                                self.assertNotIn('error', report, report)
                                return report
                            ready = receive()
                            self.assertEqual(ready['ready']['uids'], [1, 1, 1])
                            self.assertEqual(ready['ready']['gids'], [1, 1, 1])
                            self.assertEqual(ready['ready']['groups'], [])
                            self.assertEqual(set(ready['ready']['caps'].values()), {0})
                            self.assertEqual(ready['accessible'], accessible)
                            self.assertEqual(len(ready['remaining_fds']), 1)
                            for round_number in range(32):
                                parent_socket.sendall(b'G')
                                # The worker is released concurrently with
                                # validation/parser work. No exact syscall
                                # interleaving or exhaustive scheduling claim.
                                validate()
                                if round_number % 8 == 0:
                                    result = subprocess.run(
                                        [sys.executable, '-I', '-B', str(path / 'verify-static-fixture'),
                                         '--artifact', str(path / 'artifact'), '--expected-sha256', expected_hash],
                                        capture_output=True, text=True, timeout=5, check=False)
                                    self.assertEqual(result.returncode, 0, result.stderr)
                                    self.assertEqual(result.stderr, '')
                                    report = json.loads(result.stdout)
                                    self.assertEqual(report['status'], 'PASS')
                                    self.assertEqual(report['sha256'], expected_hash)
                                    self.assertEqual(report['bytes'], len(payload))
                                observed = receive()
                                self.assertEqual(observed['round'], round_number)
                                self.assertEqual(set(observed['denials']), {
                                    'read_capture', 'write_checker', 'create_child',
                                    'rename_child', 'symlink_parent'})
                                self.assertTrue(all(code in (errno.EACCES, errno.EPERM)
                                                    for code in observed['denials'].values()))
                                print('L1 concurrent evidence:', json.dumps({
                                    'accessible': accessible, 'identity': ready,
                                    'observation': observed}, sort_keys=True))
                            deadline = time.monotonic() + 5
                            while time.monotonic() < deadline:
                                found, status = os.waitpid(pid, os.WNOHANG)
                                if found == pid:
                                    reaped = True
                                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                                    break
                                time.sleep(0.01)
                            self.assertTrue(reaped, 'worker exit deadline exceeded')
                            validate()
                            self.assertEqual((path / 'artifact').read_bytes(), payload)
                            self.assertEqual((path / 'verify-static-fixture').read_bytes(), checker)
                        finally:
                            reader.close()
                            parent_socket.close()
                            if not reaped:
                                # Only our unreaped child, never an arbitrary PID.
                                try:
                                    os.kill(pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                os.waitpid(pid, 0)
                    self.assert_empty()
                finally:
                    self.base.chmod(0o700)
                    self.parent.chmod(0o700)

    def test_read_artifact_uses_fixed_private_staging_despite_poisoned_temp(self):
        repo, artifact = fixture_checkout(self.base)
        builder = load_tool('build-management-rootfs', repo)
        self.assertEqual(builder.CHECKER_STAGING_PARENT, Path('/run'))
        pin = builder.reviewed_artifact(builder.source_snapshot(builder.SOURCE_ROOT))
        payload = artifact.read_bytes()
        checker_bytes = builder.STATIC_VERIFIER.read_bytes()
        poison = self.base / 'ambient-temp'
        poison.mkdir(mode=0o777)
        observed = []
        real_run = builder.subprocess.run
        def inspect_real_parser(argv, **kwargs):
            checker, capture = Path(argv[3]), Path(argv[5])
            observed.append({'checker': checker, 'capture': capture,
                             'mode': stat.S_IMODE(checker.parent.stat().st_mode),
                             'owner': checker.parent.stat().st_uid,
                             'checker_bytes': checker.read_bytes(),
                             'capture_bytes': capture.read_bytes()})
            return real_run(argv, **kwargs)
        with mock.patch.dict(os.environ, {k: str(poison) for k in ('TMPDIR', 'TEMP', 'TMP')}), \
                mock.patch.object(tempfile, 'tempdir', str(poison)), \
                mock.patch.object(builder, 'private_checker_files', wraps=builder.private_checker_files) as staging, \
                mock.patch.object(builder.subprocess, 'run', side_effect=inspect_real_parser) as parser:
            accepted = builder.read_artifact(artifact, pin)
        # Observe the actual caller/parser path, not only direct helper tests.
        self.assertEqual(accepted, payload)
        staging.assert_called_once_with(payload, checker_bytes)
        parser.assert_called_once()
        self.assertEqual(len(observed), 1)
        record = observed[0]
        self.assertEqual(record['checker'].parent.parent, Path('/run'))
        self.assertTrue(record['checker'].parent.name.startswith('.sl-w1-elf-'))
        self.assertEqual(record['checker'].parent, record['capture'].parent)
        self.assertEqual((record['mode'], record['owner']), (0o700, 0))
        self.assertEqual(record['checker_bytes'], checker_bytes)
        self.assertEqual(record['capture_bytes'], payload)
        self.assertFalse(record['checker'].parent.exists())
        self.assertEqual(list(poison.iterdir()), [])

    def test_read_artifact_rejects_post_parser_leaf_substitution_automatically(self):
        repo, artifact = fixture_checkout(self.base)
        builder = load_tool('build-management-rootfs', repo)
        pin = builder.reviewed_artifact(builder.source_snapshot(builder.SOURCE_ROOT))
        real_run = builder.subprocess.run
        observed = []
        def replace_after_real_parser(argv, **kwargs):
            result = real_run(argv, **kwargs)
            checker = Path(argv[3])
            # Deliberate trusted-root fault injection after real parser success,
            # not an unprivileged attack or a manual call to validate().
            original = checker.read_bytes()
            checker.unlink()
            checker.write_bytes(original + b'\n# injected post-parser replacement\n')
            checker.chmod(0o400)
            observed.append((checker.parent, result))
            return result
        accepted, rejection = None, None
        with mock.patch.object(builder.subprocess, 'run', side_effect=replace_after_real_parser) as parser:
            try:
                accepted = builder.read_artifact(artifact, pin)
            except builder.BuildError as error:
                rejection = error
        parser.assert_called_once()
        self.assertEqual(len(observed), 1)
        path, result = observed[0]
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(json.loads(result.stdout)['status'], 'PASS')
        self.assertIsNone(accepted, 'caller accepted bytes after post-parser staging substitution')
        self.assertIsInstance(rejection, builder.BuildError)
        self.assertIn('checker staging file metadata/substitution', str(rejection))
        self.assertFalse(path.exists())

    def test_real_parser_roundtrip_and_timeout_leave_no_staging(self):
        repo, artifact = fixture_checkout(self.base)
        builder = load_tool('build-management-rootfs', repo)
        builder.CHECKER_STAGING_PARENT = self.parent
        source = builder.source_snapshot(builder.SOURCE_ROOT)
        pin = builder.reviewed_artifact(source)
        self.assertEqual(builder.read_artifact(artifact, pin), artifact.read_bytes())
        self.assert_empty()
        with mock.patch.object(builder.subprocess, 'run', side_effect=subprocess.TimeoutExpired('checker', 30)):
            with self.assertRaises(builder.BuildError):
                builder.read_artifact(artifact, pin)
        self.assert_empty()


if __name__ == '__main__':
    unittest.main()
