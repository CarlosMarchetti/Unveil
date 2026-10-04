"""Read PE modules into Unicorn memory, never into the host's native loader.

This models address space and symbol lookup, not DLL initialization or the PEB.
Imports receive explicit probe sentinels and are resolved lazily by the probe.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import struct
from typing import Callable

import pefile

from .api_models import UnsupportedAPI


def module_name(name: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}', name):
        raise UnsupportedAPI('Module lookup requires a basename, not a path')
    if '.' not in name:
        name += '.dll'
    if not name.lower().endswith('.dll'):
        raise UnsupportedAPI('Only DLL dependencies are supported')
    return name.casefold()


def read_guest_string(machine, address: int, *, wide=False, limit=260) -> str:
    import unicorn
    step = 2 if wide else 1
    value = bytearray()
    try:
        for index in range(limit):
            chunk = bytes(machine.mem_read(address + index * step, step))
            if chunk == bytes(step):
                return value.decode('utf-16le' if wide else 'ascii')
            value.extend(chunk)
    except (unicorn.UcError, UnicodeError) as error:
        raise UnsupportedAPI('Invalid guest string pointer or encoding') from error
    raise UnsupportedAPI('Guest string exceeds lookup budget or lacks terminator')


@dataclass(frozen=True)
class Export:
    rva: int
    forwarder: str | None = None


@dataclass
class Module:
    name: str
    base: int
    size: int
    names: dict[str, Export] = field(default_factory=dict)
    ordinals: dict[int, Export] = field(default_factory=dict)
    executable_ranges: list[tuple[int, int]] = field(default_factory=list)
    tls_rva: int = 0
    entry_point: int = 0
    path: str | None = None
    digest: str | None = None
    relocations: int = 0
    imports: int = 0
    delay_imports: int = 0
    dependencies: set[str] = field(default_factory=set)


def populate_exports(module: Module, image, rva: int, length: int):
    if not rva and not length:
        return
    size = len(image)

    def check(address, count):
        if count < 0 or not 0 <= address <= size - count:
            raise UnsupportedAPI('Export table/address exceeds image')

    def string(address, end=None):
        check(address, 1)
        end = min(size, address + 4096, size if end is None else end)
        terminator = image.find(b'\0', address, end)
        if terminator < 0:
            raise UnsupportedAPI('Unterminated export string')
        try:
            return image[address:terminator].decode('ascii')
        except UnicodeError as error:
            raise UnsupportedAPI('Non-ASCII export symbol') from error

    if not rva or length < 40:
        raise UnsupportedAPI('Truncated export directory')
    check(rva, length)
    fields = struct.unpack_from('<IIHHIIIIIII', image, rva)
    ordinal_base, count, named, eat, name_table, ordinal_table = fields[5:]
    if count > 65536 or named > 65536 or named > count:
        raise UnsupportedAPI('Export table exceeds symbol budget')
    check(eat, count * 4)
    check(name_table, named * 4)
    check(ordinal_table, named * 2)
    if ordinal_base + count > 0x10000:
        raise UnsupportedAPI('Export ordinals exceed Win32 lookup range')
    for index in range(count):
        address = struct.unpack_from('<I', image, eat + 4 * index)[0]
        if not address:
            continue
        check(address, 1)
        forwarder = string(address, rva + length) if rva <= address < rva + length else None
        module.ordinals[ordinal_base + index] = Export(address, forwarder)
    for index in range(named):
        address = struct.unpack_from('<I', image, name_table + 4 * index)[0]
        ordinal = struct.unpack_from('<H', image, ordinal_table + 2 * index)[0]
        if ordinal >= count:
            raise UnsupportedAPI('Export name ordinal exceeds address table')
        name = string(address)
        if name in module.names:
            raise UnsupportedAPI('Duplicate export name')
        if ordinal_base + ordinal in module.ordinals:
            module.names[name] = module.ordinals[ordinal_base + ordinal]


class ModuleLoader:
    def __init__(self, machine, directories, main_name, main_base, main_size,
                 register_import: Callable[[str, str | int], int], *,
                 startup_modules=(), budget=256 * 1024 * 1024, max_modules=64, main_pe=None,
                 on_module_loaded=None):
        self.machine = machine
        if len(directories) > 8:
            raise ValueError('At most 8 module search roots are supported')
        self.directories = tuple(Path(path).resolve(strict=True) for path in directories)
        if any(not path.is_dir() for path in self.directories):
            raise ValueError('Module search roots must be directories')
        self.main = Module(Path(main_name).name.casefold(), main_base, main_size)
        self.modules = {self.main.name: self.main}
        self.by_handle = {main_base: self.main}
        self.startup = {module_name(name) for name in startup_modules}
        self.register_import = register_import
        self.budget = budget
        self.max_modules = max_modules
        self.allocated = 0
        self.next_base = 0x730000000000
        self.export_labels: dict[int, str] = {}
        self.resolutions: list[dict] = []
        self.lookup_count = 0
        self.on_module_loaded = on_module_loaded
        self.module_lookups = []
        self.module_lookup_count = 0
        if main_pe is not None and len(main_pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            directory = main_pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
            if directory.VirtualAddress or directory.Size:
                populate_exports(self.main, bytes(machine.mem_read(main_base, main_size)),
                                 directory.VirtualAddress, directory.Size)

    def _file(self, name: str) -> Path:
        for root in self.directories:
            # Case-insensitive lookup also works with authored fixtures on POSIX.
            candidates = [path for path in root.iterdir() if path.name.casefold() == name]
            if len(candidates) > 1:
                raise UnsupportedAPI(f'Ambiguous module basename: {name}')
            if candidates:
                path = candidates[0].resolve(strict=True)
                if path.parent != root or not path.is_file():
                    raise UnsupportedAPI('Module escaped the configured search root')
                return path
        raise UnsupportedAPI(f'Module not found in configured search roots: {name}')

    def get_handle(self, name: str | None) -> int:
        if name is None or name.casefold() == self.main.name:
            result = self.main.base
        else:
            key = module_name(name)
            if key in self.modules:
                result = self.modules[key].base
            elif key in self.startup:
                # Imports represent startup dependencies, materialized lazily.
                result = self.load(key).base
            else:
                result = 0
        self.module_lookup_count += 1
        if len(self.module_lookups) < 256:
            self.module_lookups.append(dict(name=name, handle=result))
        return result

    def load(self, name: str) -> Module:
        from unicorn import UcError
        key = module_name(name)
        if key in self.modules:
            return self.modules[key]
        if len(self.modules) - 1 >= self.max_modules:
            raise UnsupportedAPI('Module count budget exceeded')
        path = self._file(key)
        if not 64 <= path.stat().st_size <= 128 * 1024 * 1024:
            raise UnsupportedAPI('Module file exceeds size budget')
        raw = path.read_bytes()
        if len(raw) > 128 * 1024 * 1024:
            raise UnsupportedAPI('Module changed beyond size budget')
        try:
            pe = pefile.PE(data=raw, fast_load=True)
        except pefile.PEFormatError as error:
            raise UnsupportedAPI(f'Invalid dependency PE: {key}: {error}') from error
        try:
            opt = pe.OPTIONAL_HEADER
            if pe.FILE_HEADER.Machine != 0x8664 or opt.Magic != 0x20b:
                raise UnsupportedAPI('Dependencies must be AMD64 PE32+')
            if not pe.FILE_HEADER.Characteristics & 0x2000:
                raise UnsupportedAPI('Dependency is not marked as a DLL')
            size = opt.SizeOfImage
            mapped_size = (size + 4095) & ~4095
            if not 0 < size <= 128 * 1024 * 1024 or mapped_size > self.budget - self.allocated:
                raise UnsupportedAPI('Module image exceeds memory budget')
            if not 1 <= len(pe.sections) <= 96:
                raise UnsupportedAPI('Invalid module section count')
            table_end = pe.sections[-1].get_file_offset() + 40
            if not table_end <= opt.SizeOfHeaders <= min(len(raw), size):
                raise UnsupportedAPI('Invalid module header range')
            image = bytearray(size)
            image[:opt.SizeOfHeaders] = raw[:opt.SizeOfHeaders]
            occupied = [(0, opt.SizeOfHeaders)]
            executable = []
            for section in pe.sections:
                rva = section.VirtualAddress
                length = max(section.Misc_VirtualSize, section.SizeOfRawData)
                end = rva + length
                if end > size or (length and any(rva < b and a < end for a, b in occupied)):
                    raise UnsupportedAPI('Overlapping/out-of-range module section')
                occupied.append((rva, end))
                start, physical = section.PointerToRawData, section.SizeOfRawData
                if physical and (start < opt.SizeOfHeaders or start + physical > len(raw)):
                    raise UnsupportedAPI('Module section exceeds file backing')
                image[rva:rva + physical] = raw[start:start + physical]
                if length and section.Characteristics & 0x20000000:
                    executable.append((rva, end))
            base = self.next_base
            module = Module(key, base, size, executable_ranges=executable,
                            entry_point=opt.AddressOfEntryPoint, path=str(path),
                            digest=hashlib.sha256(raw).hexdigest())

            def check(rva, length):
                if length < 0 or not 0 <= rva <= size - length:
                    raise UnsupportedAPI('Module directory/address exceeds image')

            def directory(index):
                if index >= len(opt.DATA_DIRECTORY):
                    return 0, 0
                value = opt.DATA_DIRECTORY[index]
                rva, length = value.VirtualAddress, value.Size
                if bool(rva) != bool(length):
                    raise UnsupportedAPI('Inconsistent module directory')
                if rva:
                    check(rva, length)
                return rva, length

            def string(rva, end=None):
                check(rva, 1)
                end = min(size, rva + 4096, size if end is None else end)
                terminator = image.find(0, rva, end)
                if terminator < 0:
                    raise UnsupportedAPI('Unterminated module string')
                try:
                    return image[rva:terminator].decode('ascii')
                except UnicodeError as error:
                    raise UnsupportedAPI('Non-ASCII module symbol') from error

            export_rva, export_size = directory(0)
            populate_exports(module, image, export_rva, export_size)

            relocation_rva, relocation_size = directory(5)
            delta = base - opt.ImageBase
            if delta and not relocation_rva:
                raise UnsupportedAPI('Rebased module lacks a relocation directory')
            position, seen = relocation_rva, set()
            while position < relocation_rva + relocation_size:
                check(position, 8)
                page, length = struct.unpack_from('<II', image, position)
                if length < 8 or length % 2 or position + length > relocation_rva + relocation_size:
                    raise UnsupportedAPI('Invalid base relocation block')
                for offset in range(position + 8, position + length, 2):
                    value = struct.unpack_from('<H', image, offset)[0]
                    kind, rva = value >> 12, page + (value & 0xfff)
                    if not kind:
                        continue
                    if kind != 10:
                        raise UnsupportedAPI('Unsupported AMD64 relocation type')
                    check(rva, 8)
                    if any(rva + offset in seen for offset in range(-7, 8)):
                        raise UnsupportedAPI('Overlapping relocation targets')
                    if rva < relocation_rva + relocation_size and relocation_rva < rva + 8:
                        raise UnsupportedAPI('Relocation target overlaps its own directory')
                    seen.add(rva)
                    value = struct.unpack_from('<Q', image, rva)[0]
                    struct.pack_into('<Q', image, rva, (value + delta) & 0xffffffffffffffff)
                position += length
            module.relocations = len(seen)
            module.tls_rva = directory(9)[0]

            # Validate import descriptors and thunks before publishing any module.
            slots = []
            def imports(index, delay=False):
                rva, length = directory(index)
                if not rva:
                    return 0
                stride = 32 if delay else 20
                end = rva + length
                total = 0
                for _descriptor in range(4096):
                    if rva + stride > end:
                        raise UnsupportedAPI('Unterminated import descriptor array')
                    fields = struct.unpack_from('<' + 'I' * (stride // 4), image, rva)
                    rva += stride
                    if not any(fields):
                        return total
                    if delay:
                        attributes, name, _handle, iat, lookup, _bound, _unload, _stamp = fields
                        if attributes != 1:
                            raise UnsupportedAPI('Only RVA-based delay imports are supported')
                    else:
                        lookup, _stamp, _chain, name, iat = fields
                    dll = module_name(string(name))
                    if not delay:
                        module.dependencies.add(dll)
                    lookup = lookup or iat
                    for thunk_index in range(65536):
                        if len(slots) >= 65536:
                            raise UnsupportedAPI('Import slot budget exceeded')
                        check(lookup + thunk_index * 8, 8)
                        check(iat + thunk_index * 8, 8)
                        thunk = struct.unpack_from('<Q', image, lookup + thunk_index * 8)[0]
                        if not thunk:
                            break
                        if thunk & (1 << 63):
                            if thunk & ~((1 << 63) | 0xffff):
                                raise UnsupportedAPI('Invalid ordinal import')
                            symbol = thunk & 0xffff
                        else:
                            check(thunk, 3)
                            symbol = string(thunk + 2)
                        slots.append((iat + thunk_index * 8, dll, symbol))
                        total += 1
                    else:
                        raise UnsupportedAPI('Unterminated import thunk array')
                raise UnsupportedAPI('Import descriptor budget exceeded')

            module.imports = imports(1)
            module.delay_imports = imports(13, delay=True)
            if len({slot for slot, _, _ in slots}) != len(slots):
                raise UnsupportedAPI('Duplicate module import slot')
            for slot, dll, symbol in slots:
                struct.pack_into('<Q', image, slot, self.register_import(dll, symbol))
            self.machine.mem_map(base, mapped_size)
            try:
                self.machine.mem_write(base, bytes(image))
            except UcError:
                self.machine.mem_unmap(base, mapped_size)
                raise
            self.modules[key] = module
            self.by_handle[base] = module
            self.startup.update(module.dependencies)
            self.allocated += mapped_size
            self.next_base += (mapped_size + 65535) & ~65535
            for name, export in module.names.items():
                if not export.forwarder:
                    self.export_labels.setdefault(base + export.rva, f'{key}!{name}')
            if self.on_module_loaded is not None:
                self.on_module_loaded(module)
            return module
        finally:
            pe.close()

    def resolve(self, handle: int, symbol: str | int) -> int:
        self.lookup_count += 1
        if self.lookup_count > 65536:
            raise UnsupportedAPI('Export lookup budget exceeded')
        address, chain = self._resolve(handle, symbol, set())
        if len(self.resolutions) < 256:
            self.resolutions.append(dict(handle=handle, symbol=symbol, address=address, chain=chain))
        return address

    def _resolve(self, handle, symbol, seen):
        module = self.by_handle.get(handle)
        if module is None:
            raise UnsupportedAPI('GetProcAddress received an unknown module handle')
        key = (module.name, symbol)
        if key in seen or len(seen) >= 16:
            raise UnsupportedAPI('Cyclic or excessive export forwarder chain')
        seen.add(key)
        export = module.ordinals.get(symbol) if isinstance(symbol, int) else module.names.get(symbol)
        label = f'{module.name}!{symbol}'
        if export is None:
            return 0, [label]
        if not export.forwarder:
            return module.base + export.rva, [label]
        try:
            dll, target = export.forwarder.rsplit('.', 1)
        except ValueError as error:
            raise UnsupportedAPI('Malformed export forwarder') from error
        if target.startswith('#'):
            if not target[1:].isdigit() or not 0 < int(target[1:]) <= 65535:
                raise UnsupportedAPI('Invalid forwarded ordinal')
            target = int(target[1:])
        dependency = self.load(dll)
        address, chain = self._resolve(dependency.base, target, seen)
        return address, [label] + chain

    def containing(self, address: int) -> Module | None:
        return next((module for module in self.modules.values()
                     if module is not self.main and module.base <= address < module.base + module.size), None)

    def report(self) -> dict:
        return dict(searchRoots=[str(path) for path in self.directories],
                    bytesMapped=self.allocated, dllInitializationExecuted=False,
                    importsResolvedLazily=True, exportLookups=self.lookup_count,
                    resolutions=self.resolutions, resolutionsTruncated=self.lookup_count > 256,
                    moduleLookups=self.module_lookups,
                    moduleLookupsTruncated=self.module_lookup_count > 256,
                    modules=[dict(name=m.name, path=m.path, sha256=m.digest, imageBase=m.base,
                                  imageSize=m.size, namedExports=len(m.names), ordinalExports=len(m.ordinals),
                                  relocations=m.relocations, imports=m.imports, delayImports=m.delay_imports,
                                  dependencies=sorted(m.dependencies),
                                  tlsRva=m.tls_rva, entryPointRva=m.entry_point)
                             for m in self.modules.values() if m is not self.main])
