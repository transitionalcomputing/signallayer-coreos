"""Synthetic hostile ELF fixtures; not binary execution or installed proof."""
import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
LOADER = importlib.machinery.SourceFileLoader("independent_static_elf", str(ROOT / "tools/verify-static-fixture"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
ELF = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(ELF)


def fixture(kind=2, dynamic=None):
    data = bytearray(512)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    programs = [(1, 5, 0, 0x400000, 0, 512, 512, 4096),
                (0x6474E551, 6, 0, 0, 0, 0, 0, 16)]
    if dynamic is not None:
        records = b"".join(struct.pack("<qQ", *record) for record in dynamic)
        data[320:320 + len(records)] = records
        programs.append((2, 6, 320, 0x400140, 0, len(records), len(records), 8))
    ELF.HEADER.pack_into(data, 0, ident, kind, 62, 1, 0x400180, 64, 0, 0,
                         64, 56, len(programs), 0, 0, 0)
    for index, program in enumerate(programs):
        ELF.PROGRAM.pack_into(data, 64 + 56 * index, *program)
    return data


class StaticELFTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "fixture"

    def tearDown(self):
        self.temp.cleanup()

    def verify(self, data):
        self.path.write_bytes(data)
        return ELF.verify_elf(self.path, hashlib.sha256(data).hexdigest())

    def refused(self, data, reason):
        with self.assertRaisesRegex(ELF.VerificationError, reason):
            self.verify(data)

    def header(self, data, field, value):
        header = list(ELF.HEADER.unpack_from(data))
        header[field] = value
        ELF.HEADER.pack_into(data, 0, *header)
        return data

    def program(self, data, index, field, value):
        program = list(ELF.PROGRAM.unpack_from(data, 64 + index * 56))
        program[field] = value
        ELF.PROGRAM.pack_into(data, 64 + index * 56, *program)
        return data

    def test_static_exec_roundtrip_is_explicitly_narrow(self):
        report = self.verify(fixture())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["elf_type"], "ET_EXEC")
        self.assertEqual(report["scope"], "development-static-ELF-only")
        self.assertEqual(report["binary_selfcontained"], "UNPROVEN-general-NSS/dlopen")
        self.assertEqual(report["installed_security_and_execution"], "UNPROVEN")

    def test_static_pie_without_runtime_dependencies(self):
        report = self.verify(fixture(kind=3, dynamic=[(0x6FFFFFFB, 0x8000000), (0, 0)]))
        self.assertEqual(report["elf_type"], "ET_DYN-static-PIE")
        self.assertTrue(report["dynamic_segment"])

    def test_dyn_without_pie_declaration_is_not_certified_as_pie(self):
        self.refused(fixture(kind=3), "DF_1_PIE")
        self.refused(fixture(kind=3, dynamic=[(0, 0)]), "DF_1_PIE")
        self.refused(fixture(kind=3, dynamic=[(0x6FFFFFFB, 0), (0, 0)]), "DF_1_PIE")
        self.refused(fixture(kind=3, dynamic=[(0x6FFFFFFB, 0x8000000),
                                             (0x6FFFFFFB, 0x8000000), (0, 0)]), "DF_1_PIE")

    def test_pinned_digest_required(self):
        self.path.write_bytes(fixture())
        for digest in (None, "", "a" * 63, "A" * 64, "x" * 64):
            with self.subTest(digest=digest), self.assertRaises(ELF.VerificationError):
                ELF.verify_elf(self.path, digest)

    def test_wrong_digest(self):
        self.path.write_bytes(fixture())
        with self.assertRaisesRegex(ELF.VerificationError, "SHA-256 mismatch"):
            ELF.verify_elf(self.path, "0" * 64)

    def test_truncated_and_non_elf(self):
        self.refused(b"\x7fELF", "truncated ELF header")
        self.refused(bytes(512), "not ELF")

    def test_wrong_class_endian_and_version(self):
        for offset, value in ((4, 1), (5, 2), (6, 2)):
            data = fixture()
            data[offset] = value
            self.refused(data, "ELF64 little-endian")

    def test_wrong_architecture_type_version_flags(self):
        for field, value in ((1, 1), (2, 183), (3, 0), (7, 1)):
            with self.subTest(field=field):
                self.refused(self.header(fixture(), field, value), "x86_64")

    def test_wrong_abi_or_padding(self):
        for offset in (7, 8, 9, 15):
            data = fixture()
            data[offset] = 9
            self.refused(data, "ABI")

    def test_invalid_program_tables(self):
        for field, value, reason in ((8, 0, "sizes"), (9, 55, "sizes"),
                                     (5, 1, "table"), (5, 500, "table"),
                                     (10, 0, "table"), (10, 65535, "table")):
            with self.subTest(field=field, value=value):
                self.refused(self.header(fixture(), field, value), reason)

    def test_interpreter_and_obsolete_shlib_rejected(self):
        for ptype in (3, 5):
            self.refused(self.program(fixture(), 1, 0, ptype), "PT_INTERP")

    def test_load_segment_truncation(self):
        self.refused(self.program(fixture(), 0, 5, 513), "truncated program segment")

    def test_load_segment_bad_size_flags_alignment(self):
        for field, value, reason in ((6, 511, "PT_LOAD"), (1, 8, "PT_LOAD"),
                                     (1, 7, "writable executable"), (7, 3, "alignment"),
                                     (3, 0x400001, "alignment")):
            self.refused(self.program(fixture(), 0, field, value), reason)

    def test_virtual_address_overflow(self):
        self.refused(self.program(fixture(), 0, 3, (1 << 64) - 128), "overflowing")

    def test_entry_must_be_file_backed_executable(self):
        self.refused(self.header(fixture(), 4, 0), "entrypoint")
        self.refused(self.program(fixture(), 0, 1, 4), "entrypoint")
        self.refused(self.header(fixture(), 4, 0x400200), "entrypoint")

    def test_gnu_stack_must_exist_and_not_execute(self):
        self.refused(self.program(fixture(), 1, 0, 0), "GNU_STACK")
        self.refused(self.program(fixture(), 1, 1, 7), "GNU_STACK")

    def test_all_dependency_and_search_tags_rejected(self):
        for tag in sorted(ELF.DEPENDENCY_TAGS):
            with self.subTest(tag=tag):
                self.refused(fixture(kind=3, dynamic=[(tag, 1), (0, 0)]), "runtime dependency")

    def test_dynamic_table_must_terminate_cleanly(self):
        self.refused(fixture(kind=3, dynamic=[(12, 64)]), "unterminated")
        self.refused(fixture(kind=3, dynamic=[(0, 1)]), "terminator")
        self.refused(fixture(kind=3, dynamic=[(0, 0), (12, 64)]), "after dynamic terminator")

    def test_dynamic_table_must_be_mapped_and_whole(self):
        data = fixture(kind=3, dynamic=[(0, 0)])
        self.refused(self.program(data, 2, 3, 0), "unmapped dynamic")
        data = fixture(kind=3, dynamic=[(0, 0)])
        self.refused(self.program(data, 2, 5, 15), "dynamic table length")

    def test_duplicate_dynamic_or_stack_rejected(self):
        data = fixture(kind=3, dynamic=[(0, 0)])
        self.refused(self.program(data, 1, 0, 2), "GNU_STACK|duplicate PT_DYNAMIC")
        data = fixture(kind=3, dynamic=[(0, 0)])
        self.refused(self.program(data, 2, 0, 0x6474E551), "GNU_STACK")

    def test_malformed_section_tables_rejected(self):
        self.refused(self.header(fixture(), 6, 500), "section header table")
        self.refused(self.header(fixture(), 13, 1), "section names")
        self.refused(self.header(fixture(), 12, 65535), "excessive section")
        data = fixture()
        for field, value in ((6, 448), (11, 64), (12, 1)):
            self.header(data, field, value)
        ELF.SECTION.pack_into(data, 448, 0, 1, 0, 0, 510, 3, 0, 0, 1, 0)
        self.refused(data, "truncated section contents")

    def test_no_load_segments(self):
        self.refused(self.program(fixture(), 0, 0, 0), "no loadable")

    def test_symlink_and_directory_are_not_artifacts(self):
        target = Path(self.temp.name) / "target"
        target.write_bytes(fixture())
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ELF.VerificationError, "safely read"):
            ELF.verify_elf(self.path, hashlib.sha256(fixture()).hexdigest())
        with self.assertRaisesRegex(ELF.VerificationError, "regular file"):
            ELF.verify_elf(Path(self.temp.name), "0" * 64)

    def test_fifo_is_rejected_without_blocking(self):
        os.mkfifo(self.path)
        with self.assertRaisesRegex(ELF.VerificationError, "regular file"):
            ELF.verify_elf(self.path, "0" * 64)

    def test_special_permission_bits_are_rejected(self):
        self.path.write_bytes(fixture())
        self.path.chmod(0o4644)
        self.assertTrue(stat.S_IMODE(self.path.stat().st_mode) & stat.S_ISUID)
        with self.assertRaisesRegex(ELF.VerificationError, "special permission"):
            ELF.verify_elf(self.path, hashlib.sha256(fixture()).hexdigest())

    def test_mutation_during_read_is_rejected(self):
        self.path.write_bytes(fixture())
        original = os.read
        changed = False

        def unstable_read(fd, count):
            nonlocal changed
            chunk = original(fd, count)
            if not changed:
                changed = True
                self.path.write_bytes(bytes(512))
            return chunk

        with mock.patch.object(ELF.os, "read", side_effect=unstable_read):
            with self.assertRaisesRegex(ELF.VerificationError, "changed while reading"):
                ELF.verify_elf(self.path, hashlib.sha256(fixture()).hexdigest())

    def test_cli_reports_failure_without_execution(self):
        self.path.write_bytes(b"not an executable")
        result = subprocess.run([sys.executable, str(ROOT / "tools/verify-static-fixture"),
                                 "--artifact", str(self.path), "--expected-sha256",
                                 hashlib.sha256(self.path.read_bytes()).hexdigest()],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('"status": "FAIL"', result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
