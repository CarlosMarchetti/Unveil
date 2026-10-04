import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from framework_fixtures import pe_bytes
from unveil.cli import main
from unveil.core.engine import analyze
from unveil.native.emulation import probe


def packed_fixture(code=None):
    # Authored CPU fixture: write RET to an empty executable section, jump to it.
    data = bytearray(0x2400)
    data[:0x200] = pe_bytes()[:0x200]
    struct.pack_into('<H', data, 0x86, 4)
    struct.pack_into('<I', data, 0x98 + 16, 0x4000)
    struct.pack_into('<II', data, 0x98 + 56, 0x6000, 0x400)
    data[0x98 + 112:0x98 + 240] = bytes(128)
    for index, (name, rva, length, raw, offset, flags) in enumerate([
        (b'.text', 0x1000, 0x1000, 0, 0, 0x60000020),
        (b'.data', 0x2000, 0x1000, 0, 0, 0xc0000040),
        (b'.vmp0', 0x3000, 0x1000, 0, 0, 0x60000020),
        (b'.vmp1', 0x4000, 0x2000, 0x2000, 0x400, 0x60000020),
    ]):
        offset_header = 0x188 + 40 * index
        data[offset_header:offset_header + 40] = bytes(40)
        data[offset_header:offset_header + 8] = name.ljust(8, b'\0')
        struct.pack_into('<IIII', data, offset_header + 8, length, rva, raw, offset)
        struct.pack_into('<I', data, offset_header + 36, flags)
    data[0x400:] = bytes(range(256)) * 32
    if code is None:
        code = (b'\x68\0\0\0\0\xe8\0\0\0\0' +
                b'\xc6\x05' + struct.pack('<i', 0x1000 - 0x4011) + b'\xc3' +
                b'\xe9' + struct.pack('<i', 0x1000 - 0x4016))
    data[0x400:0x400 + len(code)] = code
    return bytes(data)


def tls_fixture(*, callbacks=0, zero_fill=16, start=0x140004900, end=0x140004904):
    data = bytearray(packed_fixture())
    struct.pack_into('<II', data, 0x98 + 112 + 9 * 8, 0x4800, 40)
    struct.pack_into('<QQQQII', data, 0xc00, start, end, 0x140002000,
                     callbacks, zero_fill, 0)
    data[0xd00:0xd04] = b'TLS!'
    return bytes(data)


def localalloc_fixture(flags=0x40, size=32, symbol=b'LocalAlloc'):
    code = (b'\xb9' + struct.pack('<I', flags) + b'\xba' + struct.pack('<I', size)
            + b'\xff\x15' + struct.pack('<i', 0x4870 - 0x4010)
            + b'\xc6\x00\x41'
            + b'\xc6\x05' + struct.pack('<i', 0x1000 - 0x401a) + b'\xc3'
            + b'\xe9' + struct.pack('<i', 0x1000 - 0x401f))
    data = bytearray(packed_fixture(code))
    struct.pack_into('<II', data, 0x98 + 112 + 8, 0x4800, 40)
    data[0xc00:0xd00] = bytes(256)
    struct.pack_into('<IIIII', data, 0xc00, 0x4860, 0, 0, 0x4880, 0x4870)
    struct.pack_into('<Q', data, 0xc60, 0x4890)
    struct.pack_into('<Q', data, 0xc70, 0x4890)
    data[0xc80:0xc8d] = b'KERNEL32.dll\0'
    data[0xc92:0xc92 + len(symbol) + 1] = symbol + b'\0'
    return bytes(data)


class UnpackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'fixture.exe'
        self.source.write_bytes(packed_fixture())

    def test_automatic_detection_and_unknown_version(self):
        report = analyze(self.source, 'plan')
        protection = report['metadata']['protection']
        self.assertEqual(protection['name'], 'VMProtect')
        self.assertEqual(protection['status'], 'suspected')
        self.assertIsNone(protection['version'])
        self.assertFalse(report['plan']['capabilities']['devirtualization'])

    def test_names_alone_are_not_sufficient(self):
        from unveil.native.protection import detect_vmprotect
        metadata = dict(sections=[dict(name=name, size=100, virtualSize=100, entropy=1, permissions='R-X')
                                  for name in ('.vmp0', '.vmp1')], imports=[], dataDirectories=[])
        self.assertIsNone(detect_vmprotect(metadata))

    def test_normal_pe_not_named_vmprotect(self):
        self.source.write_bytes(pe_bytes())
        self.assertIsNone(analyze(self.source)['metadata']['protection'])

    def test_capture_is_mapped_image_not_unpacked_executable(self):
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'candidate_transition')
        self.assertEqual(result['transitionRva'], 0x1000)
        self.assertEqual(output.stat().st_size, 0x6000)
        self.assertEqual(output.read_bytes()[0x1000], 0xc3)
        self.assertEqual(self.source.read_bytes(), packed_fixture())

    def test_unmapped_access_stops_without_output(self):
        self.source.write_bytes(packed_fixture(b'\x48\xa1' + (0xdead0000).to_bytes(8, 'little')))
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'unmapped_memory')
        self.assertFalse(output.exists())

    def test_syscall_never_forwarded(self):
        self.source.write_bytes(packed_fixture(b'\x0f\x05'))
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'unmodeled_instruction')
        self.assertEqual(result['mnemonic'], 'syscall')
        self.assertFalse(output.exists())

    def test_instruction_budget(self):
        self.source.write_bytes(packed_fixture(b'\xeb\xfe'))
        result = probe(self.source, self.root / 'candidate.bin', max_instructions=20)
        self.assertEqual(result['instructions'], 20)
        self.assertFalse(result['captured'])

    def test_static_tls_reaches_candidate(self):
        self.source.write_bytes(tls_fixture())
        result = probe(self.source, self.root / 'candidate.bin')
        self.assertEqual(result['reason'], 'candidate_transition')
        self.assertEqual(result['tls']['templateBytes'], 4)
        self.assertEqual(result['tls']['zeroFillBytes'], 16)

    def test_tls_template_index_and_gs_vector(self):
        import pefile
        import unicorn
        from unicorn.x86_const import UC_X86_REG_GS_BASE
        from unveil.native.emulation import initialize_tls
        pe = pefile.PE(data=tls_fixture(), fast_load=True)
        self.addCleanup(pe.close)
        machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        base = pe.OPTIONAL_HEADER.ImageBase
        machine.mem_map(base, 0x6000)
        machine.mem_write(base, pe.get_memory_mapped_image())
        machine.mem_write(base + 0x2000, b'\xff' * 4)
        initialize_tls(machine, pe, base, 0x6000)
        teb = machine.reg_read(UC_X86_REG_GS_BASE)
        vector = int.from_bytes(machine.mem_read(teb + 0x58, 8), 'little')
        storage = int.from_bytes(machine.mem_read(vector, 8), 'little')
        self.assertEqual(bytes(machine.mem_read(storage, 20)), b'TLS!' + bytes(16))
        self.assertEqual(bytes(machine.mem_read(base + 0x2000, 4)), bytes(4))

    def test_tls_callback_blocks_before_execution(self):
        data = bytearray(tls_fixture(callbacks=0x140004a00))
        struct.pack_into('<Q', data, 0xe00, 0x140004000)
        self.source.write_bytes(data)
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'tls_callbacks_not_modeled')
        self.assertEqual(result['instructions'], 0)
        self.assertFalse(output.exists())

    def test_empty_callback_array_supported(self):
        data = bytearray(tls_fixture(callbacks=0x140004a00))
        data[0xe00:0xe08] = bytes(8)
        self.source.write_bytes(data)
        self.assertTrue(probe(self.source, self.root / 'candidate.bin')['captured'])

    def test_invalid_tls_rejected_without_capture(self):
        for kwargs in [dict(start=0x140006000, end=0x140006004),
                       dict(end=0x140004800), dict(zero_fill=1024 * 1024),
                       dict(callbacks=0x140006000)]:
            with self.subTest(kwargs=kwargs):
                self.source.write_bytes(tls_fixture(**kwargs))
                output = self.root / 'candidate.bin'
                with self.assertRaises(ValueError):
                    probe(self.source, output)
                self.assertFalse(output.exists())

    def test_localalloc_call_returns_writable_memory(self):
        self.source.write_bytes(localalloc_fixture())
        result = probe(self.source, self.root / 'candidate.bin')
        self.assertTrue(result['captured'])
        self.assertEqual(result['apiModels']['localAllocCalls'], 1)
        self.assertEqual(result['apiModels']['heapBytesAllocated'], 4096)

    def test_unsupported_allocation_blocks(self):
        for flags, size in [(2, 32), (0x40, 0), (0, 64 * 1024 * 1024 + 1)]:
            with self.subTest(flags=flags, size=size):
                self.source.write_bytes(localalloc_fixture(flags, size))
                result = probe(self.source, self.root / 'candidate.bin')
                self.assertEqual(result['reason'], 'unsupported_api_arguments')
                self.assertFalse(result['captured'])

    def test_unknown_import_is_never_forwarded(self):
        self.source.write_bytes(localalloc_fixture(symbol=b'ExitProcess'))
        result = probe(self.source, self.root / 'candidate.bin')
        self.assertEqual(result['reason'], 'unmodeled_import')
        self.assertEqual(result['importName'], 'KERNEL32.dll!ExitProcess')
        self.assertFalse(result['captured'])

    def test_rdtsc_blocks_by_default_and_can_be_modeled(self):
        # Persist EDX:EAX into the captured image to check the modeled value.
        code = (b'\x0f\x31' + b'\x89\x05' + struct.pack('<i', 0x2000 - 0x4008)
                + b'\x89\x15' + struct.pack('<i', 0x2004 - 0x400e)
                + b'\xc6\x05' + struct.pack('<i', 0x1000 - 0x4015) + b'\xc3'
                + b'\xe9' + struct.pack('<i', 0x1000 - 0x401a))
        self.source.write_bytes(packed_fixture(code))
        output = self.root / 'candidate.bin'
        self.assertEqual(probe(self.source, output)['reason'], 'unmodeled_instruction')
        self.assertFalse(output.exists())
        result = probe(self.source, output, model_tsc=True)
        self.assertTrue(result['captured'])
        self.assertEqual(result['timingModel']['rdtscReads'], 1)
        self.assertEqual(struct.unpack_from('<Q', output.read_bytes(), 0x2000)[0], 100)

    def test_clock_option_requires_emulation(self):
        with patch('sys.stderr', io.StringIO()):
            self.assertEqual(main(['unpack', str(self.source), '--model-tsc']), 1)

    def test_peb_build_read_requires_profile_and_copies_value(self):
        code = (b'\x65\x48\x8b\x04\x25\x60\0\0\0'
                + b'\x0f\xb7\x80\x20\x01\0\0')
        code += b'\x89\x05' + struct.pack('<i', 0x2000 - (0x4000 + len(code) + 6))
        code += b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3'
        code += b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5))
        self.source.write_bytes(packed_fixture(code))
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'unmodeled_environment_field')
        self.assertFalse(output.exists())
        result = probe(self.source, output, windows_version='10.0.19045')
        self.assertTrue(result['captured'])
        self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 19045)
        self.assertFalse(result['windowsEnvironment']['capturedProcessState'])

    def test_forbidden_opcode_filter_preserves_instruction_blocks(self):
        from unveil.native.emulation import needs_instruction_decode
        for code in (b'\x0f\x05', b'\x66\x0f\x05', b'\x0f\xa2', b'\x0f\x31',
                     b'\x0f\x01\xf9', b'\xf3\x0f\xc7\xf0', b'\x48\x0f\x07',
                     b'\xcc', b'\xcd\x80', b'\xf1', b'\xf4', b'\xe4\x80',
                     b'\x66\xed', b'\xf3\x6c', b'\x66\x6f'):
            with self.subTest(code=code):
                self.assertTrue(needs_instruction_decode(code))
        for code in (b'\x90', b'\x48\x89\xc1', b'\x65\x48\x8b\x04\x25\x60\0\0\0'):
            self.assertFalse(needs_instruction_decode(code))

    def test_prefixed_syscall_still_blocks(self):
        self.source.write_bytes(packed_fixture(b'\x66\x0f\x05'))
        result = probe(self.source, self.root / 'candidate.bin')
        self.assertEqual(result['reason'], 'unmodeled_instruction')
        self.assertEqual(result['mnemonic'], 'syscall')

    def test_modified_cached_code_is_checked_again(self):
        # Execute two NOPs once, replace them with SYSCALL, and revisit that address.
        code = b'\x90\x90\xe9' + struct.pack('<i', 0x4010 - 0x4007) + bytes([0x90]) * 9
        code += b'\x66\xc7\x05' + struct.pack('<i', 0x4000 - 0x4019) + b'\x0f\x05'
        code += b'\xe9' + struct.pack('<i', 0x4000 - 0x401e)
        self.source.write_bytes(packed_fixture(code))
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'unmodeled_instruction', result)
        self.assertEqual(result['mnemonic'], 'syscall')
        self.assertFalse(output.exists())

    def test_windows_version_option_validation(self):
        for args in (['--windows-version', '10.0.19045'],
                     ['--emulate', '--windows-version', '10.0.65536', '-o', str(self.root / 'candidate.bin')]):
            with patch('sys.stderr', io.StringIO()):
                self.assertEqual(main(['unpack', str(self.source)] + args), 1)

    def test_debugger_api_respects_profile_in_worker(self):
        data = bytearray(localalloc_fixture(symbol=b'IsDebuggerPresent'))
        code = b'\xff\x15' + struct.pack('<i', 0x4870 - 0x4006)
        code += b'\x89\x05' + struct.pack('<i', 0x2000 - (0x4000 + len(code) + 6))
        code += b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3'
        code += b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5))
        data[0x400:0x400 + len(code)] = code
        self.source.write_bytes(data)
        output = self.root / 'candidate.bin'
        for enabled in (False, True):
            stdout = io.StringIO()
            with self.subTest(enabled=enabled), patch('sys.stdout', stdout):
                code = main(['unpack', str(self.source), '--emulate', '-o', str(output)]
                            + (['--debugged'] if enabled else []))
                self.assertEqual(code, 2)
                self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], int(enabled))
                self.assertEqual(json.loads(stdout.getvalue())['unpacking']['windowsEnvironment']['beingDebugged'], int(enabled))

    def test_remote_debugger_query_writes_flag_and_returns_success(self):
        data = bytearray(localalloc_fixture(symbol=b'CheckRemoteDebuggerPresent'))
        code = b'\x48\xc7\xc1\xff\xff\xff\xff' + b'\x48\xba' + struct.pack('<Q', 0x140002000)
        code += b'\xff\x15' + struct.pack('<i', 0x4870 - (0x4000 + len(code) + 6))
        code += b'\x89\x05' + struct.pack('<i', 0x2004 - (0x4000 + len(code) + 6))
        code += b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3'
        code += b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5))
        data[0x400:0x400 + len(code)] = code
        self.source.write_bytes(data)
        output = self.root / 'candidate.bin'
        for debugged in (False, True):
            with self.subTest(debugged=debugged):
                result = probe(self.source, output, debugged=debugged)
                self.assertTrue(result['captured'])
                self.assertEqual(struct.unpack_from('<II', output.read_bytes(), 0x2000), (int(debugged), 1))
        # A real host process handle is never accepted or queried.
        data[0x403:0x407] = struct.pack('<I', 1234)
        self.source.write_bytes(data)
        self.assertEqual(probe(self.source, output)['reason'], 'unsupported_api_arguments')

    def test_nt_query_reads_fifth_stack_argument_and_returns_status(self):
        data = bytearray(localalloc_fixture(symbol=b'NtQueryInformationProcess'))
        data[0xc80:0xc8d] = b'ntdll.dll\0' + bytes(3)
        code = b'\x48\xc7\xc1\xff\xff\xff\xff' + b'\xba\x07\0\0\0'
        code += b'\x49\xb8' + struct.pack('<Q', 0x140002000) + b'\x41\xb9\x08\0\0\0'
        code += b'\x48\x83\xec\x38' + b'\x48\xb8' + struct.pack('<Q', 0x140002008)
        code += b'\x48\x89\x44\x24\x20'
        code += b'\xff\x15' + struct.pack('<i', 0x4870 - (0x4000 + len(code) + 6))
        code += b'\x48\x83\xc4\x38'
        code += b'\x89\x05' + struct.pack('<i', 0x200c - (0x4000 + len(code) + 6))
        code += b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3'
        code += b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5))
        data[0x400:0x400 + len(code)] = code
        self.source.write_bytes(data)
        output = self.root / 'candidate.bin'
        for debugged in (False, True):
            with self.subTest(debugged=debugged):
                result = probe(self.source, output, debugged=debugged)
                self.assertTrue(result['captured'], result)
                self.assertEqual(struct.unpack_from('<QII', output.read_bytes(), 0x2000),
                                 (0xffffffffffffffff if debugged else 0, 8, 0))

    def test_nt_set_thread_information_model_tracks_state(self):
        data = bytearray(localalloc_fixture(symbol=b'NtSetInformationThread'))
        data[0xc80:0xc8d] = b'ntdll.dll\0' + bytes(3)
        code = (b'\x48\xc7\xc1\xfe\xff\xff\xff' + b'\xba\x11\0\0\0'
                + b'\x45\x31\xc0' + b'\x45\x31\xc9')
        code += b'\xff\x15' + struct.pack('<i', 0x4870 - (0x4000 + len(code) + 6))
        code += b'\x89\x05' + struct.pack('<i', 0x2000 - (0x4000 + len(code) + 6))
        code += b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3'
        code += b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5))
        data[0x400:0x400 + len(code)] = code
        self.source.write_bytes(data)
        output = self.root / 'candidate.bin'
        result = probe(self.source, output)
        self.assertTrue(result['captured'], result)
        self.assertTrue(result['windowsEnvironment']['threadHiddenFromDebugger'])
        self.assertEqual(struct.unpack_from('<I', output.read_bytes(), 0x2000)[0], 0)
        data[0x403:0x407] = struct.pack('<I', 1234)
        self.source.write_bytes(data)
        result = probe(self.source, output)
        self.assertEqual(result['reason'], 'unsupported_api_arguments')
        self.assertEqual(result['apiArguments'], [1234, 17, 0, 0])

    def test_no_emulation_without_opt_in(self):
        stdout = io.StringIO()
        with patch('sys.stdout', stdout), patch('unveil.native.unpack.subprocess.run', side_effect=AssertionError('No probe')):
            # PE analysis itself also uses subprocess, so provide its real report first.
            with patch('unveil.native.unpack.unpack_plan', return_value={}), patch('unveil.native.unpack.analyze', return_value=dict(
                input=dict(type='PE'), status='completed', output=None, metadata={}, plan={})):
                from unveil.native.unpack import run
                from types import SimpleNamespace
                report = run(SimpleNamespace(input=self.source, output=None, report=None, emulate=False))
        self.assertEqual(report['unpacking']['reason'], 'emulation_opt_in_required')

    def test_cli_capture_reports_partial_and_schema(self):
        output, report_path = self.root / 'candidate.bin', self.root / 'report.json'
        stdout = io.StringIO()
        with patch('sys.stdout', stdout):
            code = main(['unpack', str(self.source), '--emulate', '-o', str(output), '--report', str(report_path)])
        self.assertEqual(code, 2)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report['status'], 'partial')
        self.assertFalse(report['unpacking']['unpacked'])
        self.assertFalse(report['unpacking']['devirtualized'])
        self.assertFalse(report['output']['verified'])
        import jsonschema
        schema = json.loads((Path(__file__).resolve().parents[1] / 'docs/report.schema.json').read_text())
        jsonschema.validate(report, schema)

    def test_failed_attempt_preserves_existing_output(self):
        self.source.write_bytes(packed_fixture(b'\x0f\x05'))
        output = self.root / 'candidate.bin'
        output.write_bytes(b'previous-result')
        with patch('sys.stdout', io.StringIO()):
            self.assertEqual(main(['unpack', str(self.source), '--emulate', '-o', str(output)]), 2)
        self.assertEqual(output.read_bytes(), b'previous-result')

    def test_output_alias_and_exe_rejected(self):
        for output in (self.source, self.root / 'misleading.exe'):
            with patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()):
                self.assertEqual(main(['unpack', str(self.source), '--emulate', '-o', str(output)]), 1)
