from pathlib import Path
import io
import json
import struct
import tempfile
import unittest
from unittest.mock import patch

import unicorn

from module_fixtures import dll_bytes, module_launcher
from unveil.native.api_models import UnsupportedAPI
from unveil.native.emulation import probe
from unveil.native.module_loader import ModuleLoader, read_guest_string
from unveil.cli import main


class ModuleLoaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.imports = {}

        def register(dll, symbol):
            key = (dll, symbol)
            if key not in self.imports:
                self.imports[key] = 0x600000000000 + 16 * len(self.imports)
            return self.imports[key]

        self.loader = ModuleLoader(self.machine, [self.root], 'sample.exe', 0x140000000, 0x2000,
                                   register, startup_modules=['fixture.dll'])

    def write(self, name='fixture.dll', **kwargs):
        (self.root / name).write_bytes(dll_bytes(name, **kwargs))

    def test_mapping_relocation_exports_and_idempotence(self):
        self.write(ordinal=7)
        module = self.loader.load('FIXTURE')
        self.assertEqual(bytes(self.machine.mem_read(module.base, 2)), b'MZ')
        self.assertEqual(int.from_bytes(self.machine.mem_read(module.base + 0x1400, 8), 'little'),
                         module.base + 0x1000)
        self.assertEqual(self.loader.resolve(module.base, 'answer'), module.base + 0x1000)
        self.assertEqual(self.loader.resolve(module.base, 7), module.base + 0x1000)
        self.assertEqual(self.loader.resolve(module.base, 'Answer'), 0)
        self.assertEqual(self.loader.resolve(module.base, 6), 0)
        self.assertIs(self.loader.load('fixture.dll'), module)
        self.assertEqual(self.loader.allocated, 0x2000)
        self.assertEqual(self.loader.report()['modules'][0]['relocations'], 1)

    def test_get_handle_does_not_load_unrelated_module(self):
        self.write()
        self.write('other.dll')
        self.assertEqual(self.loader.get_handle(None), 0x140000000)
        self.assertEqual(self.loader.get_handle('SAMPLE.EXE'), 0x140000000)
        self.assertEqual(self.loader.get_handle('other.dll'), 0)
        self.assertNotEqual(self.loader.get_handle('fixture.dll'), 0)
        self.assertEqual(self.loader.get_handle('other.dll'), 0)
        loaded = self.loader.load('other.dll')
        self.assertEqual(self.loader.get_handle('other.dll'), loaded.base)

    def test_forwarded_name_and_ordinal(self):
        self.write(forwarder='second.answer')
        self.write('second.dll', forwarder='third.#7')
        self.write('third.dll', ordinal=7)
        module = self.loader.load('fixture.dll')
        address = self.loader.resolve(module.base, 'answer')
        self.assertEqual(address, self.loader.modules['third.dll'].base + 0x1000)
        self.assertEqual(len(self.loader.report()['resolutions'][0]['chain']), 3)

    def test_lazy_dependency_executes_with_correct_return_stack(self):
        self.write('second.dll')
        data = bytearray(dll_bytes('kernel32.dll', dependency='second.dll'))
        # The root export calls an import in the second DLL and returns its value.
        code = (b'\x48\x83\xec\x28' + b'\xff\x15' + struct.pack('<i', 0x1670 - 0x100a)
                + b'\x48\x83\xc4\x28\xc3')
        data[0x200:0x200 + len(code)] = code
        (self.root / 'kernel32.dll').write_bytes(data)
        source, output = self.root / 'sample.exe', self.root / 'candidate.bin'
        source.write_bytes(module_launcher())
        result = probe(source, output, module_dirs=[self.root])
        self.assertTrue(result['captured'], result)
        self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 42)
        self.assertEqual([m['name'] for m in result['moduleLoader']['modules']],
                         ['kernel32.dll', 'second.dll'])
        self.assertEqual(result['moduleLoader']['exportLookups'], 2)

    def test_cyclic_forwarder_rejected(self):
        self.write(forwarder='second.answer')
        self.write('second.dll', forwarder='fixture.answer')
        module = self.loader.load('fixture.dll')
        with self.assertRaisesRegex(UnsupportedAPI, 'Cyclic'):
            self.loader.resolve(module.base, 'answer')

    def test_imports_and_delay_imports_use_guest_sentinels(self):
        self.write(dependency='second.dll', delay_dependency='third.dll')
        self.write('second.dll')
        self.write('third.dll')
        module = self.loader.load('fixture.dll')
        self.assertEqual(int.from_bytes(self.machine.mem_read(module.base + 0x1670, 8), 'little'),
                         self.imports[('second.dll', 'answer')])
        self.assertEqual(int.from_bytes(self.machine.mem_read(module.base + 0x1770, 8), 'little'),
                         self.imports[('third.dll', 'answer')])
        self.assertNotEqual(self.loader.get_handle('second.dll'), 0)
        self.assertEqual(self.loader.get_handle('third.dll'), 0)
        self.assertEqual(module.imports, 1)
        self.assertEqual(module.delay_imports, 1)

    def test_missing_and_path_module_rejected(self):
        for name in ('../fixture.dll', 'C:\\fixture.dll', '/fixture.dll', 'missing.dll', 'file.exe'):
            with self.subTest(name=name), self.assertRaises(UnsupportedAPI):
                self.loader.load(name)
        self.assertEqual(self.loader.allocated, 0)

    def test_invalid_module_does_not_publish(self):
        for offset, fmt, value in [(0x84, '<H', 0x14c), (0x188 + 8, '<I', 0x5000),
                                   (0x188 + 20, '<I', 0x9000), (0x700 + 8, '<H', 0x3400),
                                   (0x460, '<I', 0x5000), (0x480, '<H', 7)]:
            with self.subTest(offset=offset):
                data = bytearray(dll_bytes())
                struct.pack_into(fmt, data, offset, value)
                (self.root / 'fixture.dll').write_bytes(data)
                with self.assertRaises(UnsupportedAPI):
                    self.loader.load('fixture.dll')
                self.assertEqual(self.loader.allocated, 0)
                self.assertNotIn('fixture.dll', self.loader.modules)

    def test_missing_relocations_and_truncated_descriptors_rejected(self):
        data = bytearray(dll_bytes())
        struct.pack_into('<II', data, 0x98 + 112 + 5 * 8, 0, 0)
        (self.root / 'fixture.dll').write_bytes(data)
        with self.assertRaisesRegex(UnsupportedAPI, 'relocation'):
            self.loader.load('fixture.dll')
        data = bytearray(dll_bytes(dependency='second.dll'))
        struct.pack_into('<I', data, 0x98 + 112 + 8 + 4, 20)
        (self.root / 'fixture.dll').write_bytes(data)
        with self.assertRaisesRegex(UnsupportedAPI, 'descriptor'):
            self.loader.load('fixture.dll')
        self.assertEqual(self.imports, {})

    def test_cumulative_module_budget(self):
        self.write()
        self.write('second.dll')
        self.loader.budget = 0x2000
        self.loader.load('fixture.dll')
        with self.assertRaisesRegex(UnsupportedAPI, 'memory budget'):
            self.loader.load('second.dll')

    def test_guest_string_reads_are_bounded(self):
        self.machine.mem_map(0x1000, 4096)
        self.machine.mem_write(0x1000, 'fixture.dll\0'.encode('utf-16le'))
        self.assertEqual(read_guest_string(self.machine, 0x1000, wide=True), 'fixture.dll')
        with self.assertRaises(UnsupportedAPI):
            read_guest_string(self.machine, 0x1000, wide=True, limit=3)
        with self.assertRaises(UnsupportedAPI):
            read_guest_string(self.machine, 0x9000)

    def test_lookup_invalid_handle(self):
        with self.assertRaisesRegex(UnsupportedAPI, 'unknown module handle'):
            self.loader.resolve(0x1234, 'answer')

    def test_launcher_load_lookup_and_execute_export(self):
        self.write('kernel32.dll')
        for options in ({}, dict(wide=True), dict(ordinal=True), dict(load=True), dict(load=True, wide=True)):
            with self.subTest(options=options):
                source, output = self.root / 'sample.exe', self.root / 'candidate.bin'
                source.write_bytes(module_launcher(**options))
                result = probe(source, output, module_dirs=[self.root])
                self.assertTrue(result['captured'], result)
                self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 42)
                self.assertEqual(result['moduleLoader']['modules'][0]['name'], 'kernel32.dll')
                self.assertEqual(result['moduleLoader']['exportLookups'], 1)

    def test_main_module_exports(self):
        source, output = self.root / 'sample.exe', self.root / 'candidate.bin'
        source.write_bytes(module_launcher(main=True))
        result = probe(source, output, module_dirs=[self.root], main_name='sample.exe')
        self.assertTrue(result['captured'], result)
        self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 42)

    def test_worker_preserves_main_basename_and_module_root(self):
        source, output = self.root / 'sample.exe', self.root / 'candidate.bin'
        source.write_bytes(module_launcher(main=True, main_lookup=True))
        stdout = io.StringIO()
        with patch('sys.stdout', stdout):
            code = main(['unpack', str(source), '--emulate', '--module-dir', str(self.root),
                         '-o', str(output)])
        self.assertEqual(code, 2)
        report = json.loads(stdout.getvalue())
        self.assertTrue(report['unpacking']['captured'])
        self.assertEqual(report['unpacking']['moduleLoader']['moduleLookups'][0]['name'], 'sample.exe')
        self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 42)

    def test_module_roots_require_emulation_and_existing_directory(self):
        source = self.root / 'sample.exe'
        source.write_bytes(module_launcher())
        for args in [[], ['--emulate', '-o', str(self.root / 'candidate.bin')]]:
            with patch('sys.stderr', io.StringIO()):
                self.assertEqual(main(['unpack', str(source), '--module-dir', str(self.root / 'missing')] + args), 1)

    def test_uninitialized_dll_code_blocks_and_preserves_output(self):
        source, output = self.root / 'sample.exe', self.root / 'candidate.bin'
        source.write_bytes(module_launcher())
        output.write_bytes(b'previous capture')
        for tls in (False, True):
            with self.subTest(tls=tls):
                data = bytearray(dll_bytes('kernel32.dll'))
                if tls:
                    struct.pack_into('<II', data, 0x98 + 112 + 9 * 8, 0x1300, 40)
                else:
                    struct.pack_into('<I', data, 0x98 + 16, 0x1000)
                (self.root / 'kernel32.dll').write_bytes(data)
                result = probe(source, output, module_dirs=[self.root])
                self.assertEqual(result['reason'], 'module_initialization_not_modeled')
                self.assertFalse(result['captured'])
                self.assertEqual(output.read_bytes(), b'previous capture')
