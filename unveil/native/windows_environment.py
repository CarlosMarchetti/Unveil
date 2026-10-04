"""Explicit, bounded AMD64 TEB/PEB model for the guest address space.

Unknown fields stop the probe instead of supplying zero as invented loader state.
Layouts follow the x64 TEB contract and Wine's winternl PEB/LDR definitions.
"""
import re
import struct

from .api_models import UnsupportedAPI


def parse_windows_version(value: str | None) -> tuple[int, int, int] | None:
    if value is None:
        return None
    if not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}', value):
        raise ValueError('Windows version must be MAJOR.MINOR.BUILD')
    version = tuple(int(part) for part in value.split('.'))
    if any(part > 65535 for part in version):
        raise ValueError('Windows version components exceed 65535')
    return version


class GuestEnvironment:
    TEB = 0x710000000000
    PEB = 0x710000200000
    REGION_SIZE = 0x40000
    LDR = PEB + 0x1000
    ENTRY_START = PEB + 0x2000
    ENTRY_STRIDE = 0x800

    def __init__(self, machine, main_base: int, *, windows_version=None, debugged=False):
        from unicorn.x86_const import UC_X86_REG_GS_BASE
        self.machine = machine
        self.version = parse_windows_version(windows_version)
        self.known = []
        self.modules = []
        self.reads = 0
        self.thread_hidden_from_debugger = False
        machine.mem_map(self.TEB, 4096)
        machine.mem_map(self.PEB, self.REGION_SIZE)
        self._write(self.PEB + 2, bytes([bool(debugged)]))
        self._write(self.TEB + 0x30, struct.pack('<Q', self.TEB))
        self._write(self.TEB + 0x60, struct.pack('<Q', self.PEB))
        self._write(self.PEB + 0x10, struct.pack('<Q', main_base))
        self._write(self.PEB + 0x18, struct.pack('<Q', self.LDR))
        self._write(self.LDR, struct.pack('<IB', 0x58, 1))
        if self.version is not None:
            self._write(self.PEB + 0x118, struct.pack('<IIII', *self.version, 2))
        for offset in (0x10, 0x20, 0x30):
            head = self.LDR + offset
            self._write(head, struct.pack('<QQ', head, head))
        machine.reg_write(UC_X86_REG_GS_BASE, self.TEB)

    def _write(self, address: int, value: bytes):
        self.machine.mem_write(address, value)
        interval = (address, address + len(value))
        if interval not in self.known:
            self.known.append(interval)

    def configure_stack(self, base: int, size: int):
        self._write(self.TEB + 8, struct.pack('<QQ', base + size, base))

    def configure_tls(self, vector: int):
        self._write(self.TEB + 0x58, struct.pack('<Q', vector))

    def is_debugger_present(self) -> int:
        return int(bool(self.machine.mem_read(self.PEB + 2, 1)[0]))

    def query_process(self, handle: int, info_class: int, output: int, length: int,
                      return_length: int) -> tuple[int, list[tuple[int, int]]]:
        """Model current-process debug queries; never issue a host syscall."""
        if handle != 0xffffffffffffffff or info_class not in (7, 30):
            raise UnsupportedAPI(f'NtQueryInformationProcess supports current-process classes 7/30 only; requested class {info_class}')
        if info_class == 30 and self.is_debugger_present():
            raise UnsupportedAPI('Debug-object handles are not modeled for a debugged guest')
        writes = []
        if return_length:
            self.machine.mem_write(return_length, struct.pack('<I', 8))
            writes.append((return_length, 4))
        if length != 8:
            return 0xc0000004, writes  # STATUS_INFO_LENGTH_MISMATCH
        if not output:
            raise UnsupportedAPI('ProcessDebugPort output pointer is null')
        port = 0xffffffffffffffff if self.is_debugger_present() else 0
        self.machine.mem_write(output, struct.pack('<Q', port))
        writes.append((output, 8))
        return (0xc0000353 if info_class == 30 else 0), writes  # STATUS_PORT_NOT_SET for absent debug object

    def set_thread_information(self, handle: int, info_class: int, buffer: int, length: int) -> int:
        """Record ThreadHideFromDebugger for the single guest thread only."""
        if handle != 0xfffffffffffffffe or info_class != 17:
            raise UnsupportedAPI(f'NtSetInformationThread supports current-thread class 17 only; requested class {info_class}')
        if length:
            return 0xc0000004  # STATUS_INFO_LENGTH_MISMATCH
        # This information class has no input buffer; it never dereferences it.
        self.thread_hidden_from_debugger = True
        return 0

    def _unicode(self, slot: int, buffer: int, text: str):
        encoded = text.encode('utf-16le')
        if len(encoded) > 0x2fe:
            raise UnsupportedAPI('Module name/path exceeds guest LDR string budget')
        self._write(buffer, encoded + bytes(2))
        self._write(slot, struct.pack('<HHIQ', len(encoded), len(encoded) + 2, 0, buffer))

    def add_module(self, module):
        if any(existing.base == module.base for existing, _ in self.modules):
            return
        if len(self.modules) >= 65:
            raise UnsupportedAPI('Guest LDR entry budget exceeded')
        entry = self.ENTRY_START + len(self.modules) * self.ENTRY_STRIDE
        self._unicode(entry + 0x48, entry + 0x100, module.path or module.name)
        self._unicode(entry + 0x58, entry + 0x400, module.name)
        self._write(entry + 0x30, struct.pack('<QQI', module.base,
                    module.base + module.entry_point if module.entry_point else 0, module.size))
        self.modules.append((module, entry))
        # Every list is doubly linked and includes its head, even for one entry.
        for head_offset, link_offset in ((0x10, 0), (0x20, 0x10), (0x30, 0x20)):
            head = self.LDR + head_offset
            nodes = [head] + [address + link_offset for _, address in self.modules]
            for index, node in enumerate(nodes):
                self._write(node, struct.pack('<QQ', nodes[(index + 1) % len(nodes)], nodes[index - 1]))

    def check_read(self, address: int, length: int) -> str | None:
        if self.TEB <= address < self.TEB + 4096:
            structure = 'TEB'
        elif self.PEB <= address < self.PEB + self.REGION_SIZE:
            structure = 'PEB/LDR'
        else:
            return None
        self.reads += 1
        # Known neighboring fields can be read together, but gaps cannot.
        cursor = address
        for start, end in sorted(self.known):
            if start <= cursor < end:
                cursor = end
            if cursor >= address + length:
                return None
        return structure

    def report(self) -> dict:
        return dict(tebAddress=self.TEB, pebAddress=self.PEB, ldrAddress=self.LDR,
                    windowsVersion='.'.join(map(str, self.version)) if self.version else None,
                    versionSource='explicit-emulation-profile' if self.version else 'unconfigured',
                    environmentReads=self.reads, moduleListEntries=len(self.modules),
                    beingDebugged=self.is_debugger_present(),
                    threadHiddenFromDebugger=self.thread_hidden_from_debugger,
                    unknownFieldsBlocked=True, capturedProcessState=False)
