import struct
import unittest

import unicorn
from unicorn.x86_const import UC_X86_REG_GS_BASE

from unveil.native.module_loader import Module
from unveil.native.windows_environment import GuestEnvironment, parse_windows_version


class WindowsEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.environment = GuestEnvironment(self.machine, 0x140000000, windows_version='10.0.19045')

    def pointer(self, address):
        return int.from_bytes(self.machine.mem_read(address, 8), 'little')

    def test_teb_peb_version_and_stack(self):
        environment = self.environment
        self.assertEqual(self.machine.reg_read(UC_X86_REG_GS_BASE), environment.TEB)
        self.assertEqual(self.pointer(environment.TEB + 0x60), environment.PEB)
        self.assertEqual(self.pointer(environment.PEB + 0x10), 0x140000000)
        self.assertEqual(struct.unpack('<IIII', self.machine.mem_read(environment.PEB + 0x118, 16)),
                         (10, 0, 19045, 2))
        environment.configure_stack(0x700000000000, 0x200000)
        self.assertEqual(self.pointer(environment.TEB + 8), 0x700000200000)
        self.assertEqual(self.pointer(environment.TEB + 16), 0x700000000000)

    def test_ldr_lists_names_and_update(self):
        environment = self.environment
        for name, base in [('sample.exe', 0x140000000), ('kernel32.dll', 0x730000000000), ('ntdll.dll', 0x730000020000)]:
            environment.add_module(Module(name, base, 0x2000))
        environment.add_module(Module('ntdll.dll', 0x730000020000, 0x2000))
        self.assertEqual(len(environment.modules), 3)
        for head_offset, link_offset in ((0x10, 0), (0x20, 0x10), (0x30, 0x20)):
            head = environment.LDR + head_offset
            node, previous = self.pointer(head), head
            names = []
            while node != head:
                self.assertEqual(self.pointer(node + 8), previous)
                entry = node - link_offset
                self.assertEqual(self.pointer(entry + 0x30), environment.modules[len(names)][0].base)
                length, maximum, _, buffer = struct.unpack('<HHIQ', self.machine.mem_read(entry + 0x58, 16))
                self.assertEqual(maximum, length + 2)
                names.append(bytes(self.machine.mem_read(buffer, length)).decode('utf-16le'))
                previous, node = node, self.pointer(node)
                self.assertLessEqual(len(names), 3)
            self.assertEqual(names, ['sample.exe', 'kernel32.dll', 'ntdll.dll'])
            self.assertEqual(self.pointer(head + 8), previous)

    def test_unknown_fields_and_partial_overlaps_block(self):
        environment = self.environment
        self.assertIsNone(environment.check_read(environment.PEB + 0x118, 16))
        self.assertEqual(environment.check_read(environment.PEB + 0x117, 8), 'PEB/LDR')
        self.assertEqual(environment.check_read(environment.PEB + 0x30, 8), 'PEB/LDR')
        self.assertEqual(environment.check_read(environment.TEB + 0x62, 8), 'TEB')

    def test_unconfigured_version_not_silently_zero(self):
        machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        environment = GuestEnvironment(machine, 0x140000000)
        self.assertEqual(environment.check_read(environment.PEB + 0x120, 2), 'PEB/LDR')
        self.assertEqual(environment.report()['versionSource'], 'unconfigured')

    def test_version_profile_validation(self):
        self.assertEqual(parse_windows_version('10.0.19045'), (10, 0, 19045))
        self.assertIsNone(parse_windows_version(None))
        for value in ('10', '10.0.-1', '10.0.65536', '10.0.19045.extra', '10.0.19045\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_windows_version(value)

    def test_debugger_model_uses_guest_flag(self):
        self.assertEqual(self.environment.is_debugger_present(), 0)
        self.machine.mem_write(self.environment.PEB + 2, b'\x01')
        self.assertEqual(self.environment.is_debugger_present(), 1)
        self.assertEqual(self.environment.report()['beingDebugged'], 1)
        machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        environment = GuestEnvironment(machine, 0x140000000, debugged=True)
        self.assertEqual(environment.is_debugger_present(), 1)

    def test_process_debug_port_and_short_buffer(self):
        self.machine.mem_map(0x1000, 4096)
        status, writes = self.environment.query_process(0xffffffffffffffff, 7, 0x1000, 8, 0x1020)
        self.assertEqual(status, 0)
        self.assertEqual(writes, [(0x1020, 4), (0x1000, 8)])
        self.assertEqual(self.pointer(0x1000), 0)
        self.machine.mem_write(self.environment.PEB + 2, b'\x01')
        self.environment.query_process(0xffffffffffffffff, 7, 0x1000, 8, 0)
        self.assertEqual(self.pointer(0x1000), 0xffffffffffffffff)
        self.machine.mem_write(0x1000, b'previous')
        status, writes = self.environment.query_process(0xffffffffffffffff, 7, 0x1000, 4, 0x1020)
        self.assertEqual(status, 0xc0000004)
        self.assertEqual(bytes(self.machine.mem_read(0x1000, 8)), b'previous')
        self.assertEqual(int.from_bytes(self.machine.mem_read(0x1020, 4), 'little'), 8)
        from unveil.native.api_models import UnsupportedAPI
        with self.assertRaises(UnsupportedAPI):
            self.environment.query_process(1234, 7, 0x1000, 8, 0)
        with self.assertRaises(UnsupportedAPI):
            self.environment.query_process(0xffffffffffffffff, 31, 0x1000, 8, 0)

    def test_absent_debug_object_is_an_ntstatus_failure(self):
        self.machine.mem_map(0x1000, 4096)
        status, writes = self.environment.query_process(0xffffffffffffffff, 30, 0x1000, 8, 0x1020)
        self.assertEqual(status, 0xc0000353)
        self.assertEqual(self.pointer(0x1000), 0)
        self.assertEqual(int.from_bytes(self.machine.mem_read(0x1020, 4), 'little'), 8)
        self.machine.mem_write(self.environment.PEB + 2, b'\x01')
        from unveil.native.api_models import UnsupportedAPI
        with self.assertRaises(UnsupportedAPI):
            self.environment.query_process(0xffffffffffffffff, 30, 0x1000, 8, 0)

    def test_current_thread_information_tracks_state_and_validates_class(self):
        from unveil.native.api_models import UnsupportedAPI
        environment = self.environment
        self.assertFalse(environment.report()['threadHiddenFromDebugger'])
        self.assertEqual(environment.set_thread_information(0xfffffffffffffffe, 17, 0, 4), 0xc0000004)
        self.assertFalse(environment.thread_hidden_from_debugger)
        self.assertEqual(environment.set_thread_information(0xfffffffffffffffe, 17, 0, 0), 0)
        self.assertTrue(environment.report()['threadHiddenFromDebugger'])
        for handle, info_class in ((1234, 17), (0xfffffffffffffffe, 0)):
            with self.assertRaises(UnsupportedAPI):
                environment.set_thread_information(handle, info_class, 0, 0)
