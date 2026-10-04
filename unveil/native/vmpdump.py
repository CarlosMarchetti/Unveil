"""External live-process import reconstruction via VMPDump (0xnobody/vmpdump, GPL-3.0).

VMPDump attaches to an already-running process that has completed VMProtect
initialization and reached its OEP, scans its mapped executable sections for
VMP import-stub patterns, lifts them with VTIL, and writes a fixed dump beside
the target module. This module only launches the external VMPDump.exe and
validates its declared output; it does not reimplement stub scanning, VTIL
lifting or import resolution, and it never starts or injects into a process.
"""
import hashlib
import re
import subprocess
from pathlib import Path

import pefile

ENTRY_POINT_RVA = re.compile(r'^[0-9a-fA-F]{1,8}$')


def inspect_imports(path):
    if Path(path).stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Backend PE exceeds 128 MiB')
    pe = pefile.PE(str(path), fast_load=True)
    try:
        size = Path(path).stat().st_size
        ranges = []
        for section in pe.sections:
            start, length = section.PointerToRawData, section.SizeOfRawData
            if length and (start < pe.OPTIONAL_HEADER.SizeOfHeaders or start + length > size or
                           any(start < end and previous < start + length for previous, end in ranges)):
                raise ValueError('Invalid backend PE section layout')
            if length:
                ranges.append((start, start + length))
        pe.parse_data_directories(directories=[1])
        imports = set()
        for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            for symbol in descriptor.imports:
                imports.add((descriptor.dll.decode('ascii', 'replace').lower(),
                             symbol.name.decode('ascii', 'replace') if symbol.name else '#' + str(symbol.ordinal)))
        return dict(machine=pe.FILE_HEADER.Machine, imports=imports,
                    entryPoint=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                    imageBase=pe.OPTIONAL_HEADER.ImageBase,
                    warnings=pe.get_warnings())
    finally:
        pe.close()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def run(executable, pid, module_name, module_path, entry_point_rva=None,
        disable_reloc=False, timeout_seconds=60):
    executable = Path(executable).resolve(strict=True)
    module_path = Path(module_path).resolve(strict=True)
    if not isinstance(pid, int) or not 0 < pid <= 0xffffffff:
        raise ValueError('pid must be a positive integer')
    if entry_point_rva is not None and not ENTRY_POINT_RVA.match(entry_point_rva):
        raise ValueError('entry_point_rva must be hex digits, no 0x prefix')
    candidate = module_path.with_name(module_path.stem + '.VMPDump' + module_path.suffix)
    if candidate.exists():
        return dict(status='blocked', reason='existing_backend_output_must_be_preserved',
                    output=None, path=str(candidate))
    before = inspect_imports(module_path)
    arguments = [str(executable), str(pid), module_name]
    if entry_point_rva is not None:
        arguments.append('-ep=' + entry_point_rva)
    if disable_reloc:
        arguments.append('-disable-reloc')
    try:
        process = subprocess.run(arguments, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                  encoding='utf-8', errors='replace', timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return dict(status='blocked', reason='vmpdump_timeout', output=None)
    result = dict(returncode=process.returncode, stdout=process.stdout[-4000:],
                  stderr=process.stderr[-4000:], output=None)
    if process.returncode:
        result.update(status='blocked', reason='vmpdump_nonzero_exit',
                      exitCodeHex=f'0x{process.returncode & 0xffffffff:08X}')
        return result
    candidate = locate_output(module_path)
    if candidate is None:
        result.update(status='blocked', reason='output_file_not_found')
        return result
    try:
        after = inspect_imports(candidate)
        if after['machine'] != before['machine']:
            raise ValueError('Backend output architecture differs from input')
    except (ValueError, pefile.PEFormatError) as error:
        result.update(status='blocked', reason='invalid_backend_pe', detail=str(error))
        return result
    added = sorted(after['imports'] - before['imports'])
    result.update(status='partial', reason='reconstructed_pe_requires_review',
                  validation=dict(structural=True, runnableVerified=False, devirtualized=False,
                                  originalImports=len(before['imports']), outputImports=len(after['imports']),
                                  addedImports=[dict(library=dll, name=name) for dll, name in added],
                                  entryPoint=after['entryPoint'], imageBase=after['imageBase'],
                                  warnings=after['warnings']),
                  output=dict(path=str(candidate), sha256=sha256(candidate),
                              size=candidate.stat().st_size))
    if not added:
        result['reason'] = 'no_additional_imports_recovered'
    return result


def locate_output(module_path):
    candidate = module_path.with_name(module_path.stem + '.VMPDump' + module_path.suffix)
    return candidate if candidate.exists() else None
