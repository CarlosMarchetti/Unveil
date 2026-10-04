"""Authored PE fixtures only; no target is executed by these tests."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from framework_fixtures import pe_bytes
from unveil.gui.model import Patch, Project, hex_bytes, parse_rva
from unveil.gui.package import export_package
from unveil.gui.search import BinaryView


class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sample = self.root / 'fixture.exe'
        data = bytearray(pe_bytes())
        struct.pack_into('<H', data, 0x96, 0x22)  # Authored EXE, rather than DLL.
        data[0x700:0x70d] = b'Hello Unveil\0'
        self.sample.write_bytes(data)
        self.project = Project.open_sample(str(self.sample))

    def test_hex_and_patch_bounds(self):
        self.assertEqual(parse_rva('1000'), 0x1000)
        self.assertEqual(hex_bytes('31 C0\nC3'), b'\x31\xc0\xc3')
        for value in ('', '1', 'zz', 'aa' * 4097):
            with self.assertRaises(ValueError):
                hex_bytes(value)
        for patch in (Patch('x', True, 'aa', 'bb'), Patch('x', 0x1fff, 'aabb', 'cc'),
                      Patch('x', 0x1000, 'aa', 'bbcc')):
            with self.assertRaises(ValueError):
                patch.validated(self.project.image_size)

    def test_overlap_and_duplicate_names_rejected(self):
        first = Patch('first', 0x1000, 'aabb', 'cc')
        for second in (Patch('second', 0x1001, 'bb', 'cc'), Patch('first', 0x1010, 'aa', 'cc')):
            with self.assertRaises(ValueError):
                replace(self.project, patches=(first, second)).validated()

    def test_project_round_trip_and_source_protection(self):
        project = replace(self.project, patches=(Patch('entry', 0x1000, 'c3', '90'),))
        path = self.root / 'project.json'
        project.save(path)
        self.assertEqual(Project.load(path), project)
        with self.assertRaises(ValueError):
            project.save(self.sample)
        value = json.loads(path.read_text())
        value['capture'] = 'false'
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            Project.load(path)

    def test_file_and_memory_addressing(self):
        view = BinaryView(self.sample)
        self.assertEqual(view.offset_to_rva(0x700), 0x1500)
        self.assertIsNone(view.offset_to_rva(0xa00))
        self.assertEqual(view.read_rva(0x1500, 5), b'Hello')
        with self.assertRaises(ValueError):
            view.read_rva(0x1900, 5)
        mapped = bytearray(0x2000)
        mapped[:0x200] = view.data[:0x200]
        mapped[0x1000:0x1800] = view.data[0x200:0xa00]
        path = self.root / 'fixture.mapped.bin'
        path.write_bytes(mapped)
        memory = BinaryView(path, True)
        hit = memory.search('Hello')[0]
        self.assertEqual((hit.offset, hit.rva), (0x1500, 0x1500))
        self.assertEqual(memory.read_rva(0x1500, 5), b'Hello')
        with self.assertRaises(ValueError):
            BinaryView(self.sample, True)

    def test_text_patch_and_hex_search(self):
        view = BinaryView(self.sample)
        hit = view.search('Hello')[0]
        expected, patch = view.text_patch(hit, 'New')
        self.assertEqual(bytes.fromhex(expected), b'Hello Unveil\0')
        self.assertEqual(len(bytes.fromhex(expected)), len(bytes.fromhex(patch)))
        self.assertTrue(bytes.fromhex(patch).startswith(b'New\0'))
        with self.assertRaises(ValueError):
            view.text_patch(hit, 'Too long for the original storage')
        self.assertEqual(view.search('48 65 6c 6c 6f', 'hex')[0].rva, 0x1500)

    def test_export_is_self_contained_and_data_stays_data(self):
        title = "$(Write-Output 'not-code')"
        project = replace(self.project, title=title,
                          patches=(Patch('quoted " name', 0x1000, 'c3', '90'),))
        destination = export_package(project, self.root / 'package')
        for folder in ('windows', 'windows-sandbox'):
            inputs = destination / folder / 'input'
            self.assertEqual((inputs / 'sample.exe').read_bytes(), self.sample.read_bytes())
            config = json.loads((inputs / 'runtime.json').read_text(encoding='utf-8-sig'))
            self.assertEqual(config['title'], title)
            self.assertEqual(config['patches'][0]['rva'], 0x1000)
            self.assertNotIn(title, (inputs / 'patch.ps1').read_text(encoding='utf-8-sig'))
        manifest = json.loads((destination / 'SHA256.json').read_text())
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((destination / name).read_bytes()).hexdigest(), digest)
        with self.assertRaises(ValueError):
            export_package(project, destination)
        launcher = (destination / 'windows-sandbox/Abrir-Sandbox.ps1').read_text(encoding='utf-8-sig')
        self.assertIn('<Networking>Disable</Networking>', launcher)
        self.assertIn('<ReadOnly>true</ReadOnly>', launcher)
        self.assertIn('.InnerText=$inputFolder', launcher)

    def test_changed_sample_export_rejected_without_partial_package(self):
        self.sample.write_bytes(self.sample.read_bytes() + b'changed')
        destination = self.root / 'package'
        with self.assertRaises(ValueError):
            export_package(self.project, destination)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == 'nt', 'PowerShell runtime verification requires Windows')
    def test_powershell_runtime_guards_and_rollback_with_mock_memory(self):
        project = replace(self.project, title='Fixture', capture=False, patches=(
            Patch('one', 0x1000, 'aa', 'cc'), Patch('two', 0x1010, 'bb', 'dd')))
        package = export_package(project, self.root / 'package')
        powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        harness = Path(__file__).with_name('gui_runtime_mock.ps1')
        for mode in ('compile', 'success', 'rollback', 'signature'):
            with self.subTest(mode=mode):
                result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive',
                                         '-ExecutionPolicy', 'Bypass', '-File', str(harness),
                                         '-Package', str(package), '-Mode', mode],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('"targetExecuted":false', result.stdout)


if __name__ == '__main__':
    unittest.main()
