"""Recover an analysis PE and addressable strings from a saved mapped image.

This preserves runtime bytes; it does not restore loader state or VM semantics.
"""
import os
from pathlib import Path
import re
import tempfile

import pefile

from unveil.core.model import sha256
from unveil.core.reporting import protect_output, write_report
from .pe import entropy


def rebuild(data, image_base):
    if not 64 <= len(data) <= 128 * 1024 * 1024:
        raise ValueError('Mapped image size outside 64 bytes..128 MiB')
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as error:
        raise ValueError(f'Invalid captured PE headers: {error}') from error
    try:
        opt = pe.OPTIONAL_HEADER
        bits = {0x10b: 32, 0x20b: 64}.get(opt.Magic)
        if not bits or not 0 < image_base < (1 << bits):
            raise ValueError('Invalid runtime image base or PE architecture')
        if len(data) != opt.SizeOfImage:
            raise ValueError('Mapped capture must contain exactly SizeOfImage bytes')
        alignment = opt.FileAlignment
        if not 512 <= alignment <= 65536 or alignment & (alignment - 1):
            raise ValueError('Unsupported file alignment')
        align = lambda n: (n + alignment - 1) & ~(alignment - 1)
        header_end = pe.sections[-1].get_file_offset() + 40 if pe.sections else 0
        if not 1 <= len(pe.sections) <= 96 or not header_end <= opt.SizeOfHeaders <= len(data):
            raise ValueError('Invalid section table or header range')
        payload = bytearray(align(opt.SizeOfHeaders))
        sections, strings = [], []
        occupied = [(0, opt.SizeOfHeaders)]
        for section in pe.sections:
            rva = section.VirtualAddress
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if rva + size > len(data) or any(rva < end and start < rva + size for start, end in occupied):
                raise ValueError('Overlapping or out-of-range mapped section')
            occupied.append((rva, rva + size))
            chunk = data[rva:rva + size]
            offset = len(payload)
            name = section.Name.rstrip(b'\0').decode('ascii', 'replace')
            item = dict(name=name, rva=rva, size=size, offset=offset,
                        originalRawSize=section.SizeOfRawData,
                        nonzeroBytes=len(chunk) - chunk.count(0), entropy=entropy(chunk))
            # Separate budgets prevent ASCII noise in code from starving UTF-16/data strings.
            counts = {}
            for encoding, pattern in [('ascii', rb'[\x20-\x7e]{6,}'),
                                      ('utf-16le', rb'(?:[\x20-\x7e]\x00){6,}')]:
                count = 0
                for match in re.finditer(pattern, chunk):
                    count += 1
                    if count <= 5000:
                        strings.append(dict(section=name, rva=rva + match.start(),
                                            va=image_base + rva + match.start(),
                                            fileOffset=offset + match.start(), encoding=encoding,
                                            value=match.group()[:2048].decode(encoding),
                                            truncated=len(match.group()) > 2048))
                counts[encoding] = dict(candidates=count, saved=min(count, 5000))
            item['strings'] = counts
            sections.append(item)
            section.PointerToRawData = offset if size else 0
            section.SizeOfRawData = align(size)
            section.PointerToRelocations = section.PointerToLinenumbers = 0
            section.NumberOfRelocations = section.NumberOfLinenumbers = 0
            payload.extend(chunk)
            payload.extend(bytes(align(size) - size))
        preferred = opt.ImageBase
        opt.ImageBase = image_base
        opt.CheckSum = 0
        pe.FILE_HEADER.PointerToSymbolTable = pe.FILE_HEADER.NumberOfSymbols = 0
        cleared = []
        # These directories include obsolete file offsets or pre-load binding state.
        for index in (4, 6, 11):
            if index < len(opt.DATA_DIRECTORY):
                directory = opt.DATA_DIRECTORY[index]
                if directory.VirtualAddress or directory.Size:
                    cleared.append(index)
                directory.VirtualAddress = directory.Size = 0
        headers = pe.write()[:opt.SizeOfHeaders]
        payload[:len(headers)] = headers
        return bytes(payload), dict(status='partial', artifactKind='analysis-pe',
                                    runnableVerified=False, unpacked=False, devirtualized=False,
                                    importsReconstructed=False, preferredImageBase=preferred,
                                    imageBase=image_base, clearedDirectories=cleared,
                                    sections=sections, strings=strings,
                                    limitations=[
                                        'Analysis layout only; entry point, imports, relocations and unwind state are not repaired.',
                                        'Strings are printable candidates from captured module pages, not decrypted strings; heap is absent.',
                                        'Runtime bytes and VMProtect sections are preserved; no virtualized function is translated.'])
    finally:
        pe.close()


def recover(source, destination, image_base, report_path=None):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    report_path = Path(report_path).resolve() if report_path else destination.with_suffix('.recovery.json')
    protect_output(destination, [source, report_path])
    protect_output(report_path, [source, destination])
    if source.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('Mapped capture exceeds 128 MiB')
    data = source.read_bytes()
    payload, result = rebuild(data, image_base)
    # Verify that a PE consumer can read every section at its preserved RVA.
    check = pefile.PE(data=payload, fast_load=True)
    try:
        for section in result['sections']:
            rva, size = section['rva'], section['size']
            if size and check.get_data(rva, size) != data[rva:rva + size]:
                raise ValueError('Rebuilt section failed byte-for-byte validation')
    finally:
        check.close()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=destination.name + '.')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    result.update(source=str(source), sourceSHA256=sha256(source), output=str(destination),
                  outputSHA256=sha256(destination), sectionBytesVerified=True)
    write_report(report_path, result, inputs=[source, destination])
    return dict(path=str(destination), report=str(report_path), sha256=result['outputSHA256'],
                artifactKind='analysis-pe', verified=False, sectionBytesVerified=True,
                stringsSaved=len(result['strings']), importsReconstructed=False, devirtualized=False)


def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Saved RVA-layout memory capture')
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('--image-base', required=True, type=lambda s: int(s, 0))
    args = parser.parse_args()
    print(json.dumps(recover(args.input, args.output, args.image_base), indent=2))


if __name__ == '__main__':
    main()
