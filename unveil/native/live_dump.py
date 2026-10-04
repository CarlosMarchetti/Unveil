"""Opt-in Windows main-module snapshots. Never writes into the target process."""
import ctypes
import os
from pathlib import Path
import time

from unveil.core.reporting import same_path

MAX_IMAGE_BYTES = 128 * 1024 * 1024


def capture_pages(reader, base, size, destination, *, timeout=30):
    """Reader returns (bytes, reason). Missing bytes are zero-filled and recorded."""
    if not 0 < size <= MAX_IMAGE_BYTES:
        raise ValueError('Live image exceeds 128 MiB capture budget')
    if not 1 <= timeout <= 120:
        raise ValueError('Dump timeout must be in 1..120 seconds')
    started = time.monotonic()
    holes = []
    read_bytes = 0
    with open(destination, 'wb') as output:
        for offset in range(0, size, 4096):
            length = min(4096, size - offset)
            if time.monotonic() - started >= timeout:
                raise TimeoutError('Live dump time budget exceeded')
            data, reason = reader(base + offset, length)
            if len(data) > length:
                raise ValueError('Process reader returned too many bytes')
            output.write(data)
            read_bytes += len(data)
            if len(data) < length:
                start, missing = offset + len(data), length - len(data)
                reason = reason or 'incomplete_read'
                output.write(bytes(missing))
                if holes and holes[-1]['rva'] + holes[-1]['size'] == start and holes[-1]['reason'] == reason:
                    holes[-1]['size'] += missing
                else:
                    holes.append(dict(rva=start, size=missing, reason=reason))
    if read_bytes == 0:
        raise ValueError('No bytes could be read from the selected module')
    return dict(bytesRead=read_bytes, imageSize=size, unreadableRanges=holes,
                completeRead=not holes, elapsedSeconds=round(time.monotonic() - started, 3))


class WindowsProcess:
    def __init__(self, pid, source):
        if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ValueError('Live dump requires Windows with 64-bit Python')
        if not isinstance(pid, int) or not 0 < pid <= 0xffffffff:
            raise ValueError('PID must be a positive 32-bit integer')
        from ctypes import wintypes as w
        self.pid, self.handle = pid, None
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
        self.kernel.QueryFullProcessImageNameW.restype = w.BOOL
        self.kernel.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel.ReadProcessMemory.restype = w.BOOL

        class ModuleInfo(ctypes.Structure):
            _fields_ = [('base', ctypes.c_void_p), ('size', w.DWORD), ('entry', ctypes.c_void_p)]

        class MemoryInfo(ctypes.Structure):
            _fields_ = [('base', ctypes.c_void_p), ('allocationBase', ctypes.c_void_p),
                        ('allocationProtect', w.DWORD), ('regionSize', ctypes.c_size_t),
                        ('state', w.DWORD), ('protect', w.DWORD), ('type', w.DWORD)]

        self.MemoryInfo = MemoryInfo
        self.kernel.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MemoryInfo), ctypes.c_size_t]
        self.kernel.VirtualQueryEx.restype = ctypes.c_size_t
        self.psapi.EnumProcessModulesEx.argtypes = [w.HANDLE, ctypes.POINTER(w.HMODULE), w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD]
        self.psapi.EnumProcessModulesEx.restype = w.BOOL
        self.psapi.GetModuleInformation.argtypes = [w.HANDLE, w.HMODULE, ctypes.POINTER(ModuleInfo), w.DWORD]
        self.psapi.GetModuleInformation.restype = w.BOOL
        self.psapi.GetModuleFileNameExW.argtypes = [w.HANDLE, w.HMODULE, w.LPWSTR, w.DWORD]
        self.psapi.GetModuleFileNameExW.restype = w.DWORD
        # QUERY_INFORMATION | VM_READ. No debug privilege, injection or VM_WRITE.
        self.handle = self.kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = w.DWORD(len(buffer))
            if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.path = Path(buffer.value)
            if not same_path(self.path, source):
                raise ValueError('PID executable does not match the input file')
            modules = (w.HMODULE * 2048)()
            needed = w.DWORD()
            if not self.psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3):
                raise ctypes.WinError(ctypes.get_last_error())
            if needed.value > ctypes.sizeof(modules):
                raise ValueError('Process module enumeration exceeds budget')
            matched = []
            for index in range(needed.value // ctypes.sizeof(w.HMODULE)):
                count = self.psapi.GetModuleFileNameExW(self.handle, modules[index], buffer, len(buffer))
                if count and count < len(buffer) and same_path(buffer.value, source):
                    matched.append(modules[index])
            if len(matched) != 1:
                raise ValueError('Main module could not be identified uniquely')
            info = ModuleInfo()
            if not self.psapi.GetModuleInformation(self.handle, matched[0], ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.base, self.size = info.base, info.size
            if not self.base or not 0 < self.size <= MAX_IMAGE_BYTES:
                raise ValueError('Invalid or oversized live image')
        except BaseException:
            self.close()
            raise

    def read(self, address, length):
        info = self.MemoryInfo()
        if not self.kernel.VirtualQueryEx(self.handle, address, ctypes.byref(info), ctypes.sizeof(info)):
            return b'', 'query_failed'
        # Skip uncommitted, guard and no-access pages without touching them.
        if info.state != 0x1000 or info.protect & (0x01 | 0x100):
            return b'', 'uncommitted_guard_or_noaccess'
        if not info.base <= address or address + length > info.base + info.regionSize:
            return b'', 'region_changed'
        buffer = ctypes.create_string_buffer(length)
        copied = ctypes.c_size_t()
        ok = self.kernel.ReadProcessMemory(self.handle, address, buffer, length, ctypes.byref(copied))
        data = buffer.raw[:min(copied.value, length)]
        return data, None if ok and len(data) == length else 'read_failed_or_partial'

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def dump(pid, source, destination, timeout=30):
    process = WindowsProcess(pid, source)
    try:
        result = capture_pages(process.read, process.base, process.size, destination, timeout=timeout)
        return dict(result, pid=pid, modulePath=str(process.path), imageBase=process.base,
                    captured=True, status='captured', reason='live_main_module_snapshot',
                    limitations=['The process was not suspended; pages may represent different instants.',
                                 'Unreadable regions are zero-filled and explicitly listed.',
                                 'Memory layout is RVA-based, not a rebuilt executable.',
                                 'Capture does not prove unpacking, an original entry point or devirtualization.'])
    finally:
        process.close()
