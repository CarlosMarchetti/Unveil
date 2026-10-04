from collections import Counter
import hashlib
import math
import re
import struct
from .protection import detect_vmprotect, unpack_plan


def entropy(data):
    if not data:
        return 0.0
    return round(-sum((count / len(data)) * math.log2(count / len(data))
                      for count in Counter(data).values()), 4)


def text(value):
    return value.decode('utf-8', 'replace') if isinstance(value, bytes) else value


def strings(data, limit=10_000):
    result = []
    for encoding, pattern in [('ascii', rb'[\x20-\x7e]{4,}'),
                              ('utf-16le', rb'(?:[\x20-\x7e]\x00){4,}')]:
        for match in re.finditer(pattern, data):
            if len(result) >= limit:
                return sorted(result, key=lambda x: x['offset']), True
            result.append(dict(offset=match.start(), encoding=encoding,
                               value=match.group()[:2048].decode(encoding),
                               truncated=len(match.group()) > 2048))
    return sorted(result, key=lambda x: x['offset']), False


class PeAnalyzer:
    id = 'native.pe'
    artifact_types = ('PE',)

    def analyze(self, context):
        import pefile
        data = context.artifact.path.read_bytes()
        if len(data) < 64:
            raise ValueError('Truncated DOS header')
        nt = struct.unpack_from('<I', data, 60)[0]
        if nt > len(data) - 24 or data[nt:nt + 4] != b'PE\0\0':
            raise ValueError('Invalid PE header range or signature')
        count = struct.unpack_from('<H', data, nt + 6)[0]
        optional = struct.unpack_from('<H', data, nt + 20)[0]
        if count > 96 or nt + 24 + optional + count * 40 > len(data):
            raise ValueError('Invalid/truncated section table or section budget exceeded')
        pe = pefile.PE(data=data, fast_load=True)
        try:
            return self._analyze(context, pe, data)
        finally:
            pe.close()

    def _analyze(self, context, pe, data):
        if pe.OPTIONAL_HEADER.Magic not in (0x10b, 0x20b):
            raise ValueError('Only PE32 and PE32+ are supported')
        diagnostics = context.diagnostics
        sections = []
        raw_ranges = []
        for section in pe.sections:
            start, size = section.PointerToRawData, section.SizeOfRawData
            if start > len(data) or size > len(data) - start:
                raise ValueError('Section raw range exceeds input')
            if size and any(start < end and previous < start + size for previous, end in raw_ranges):
                diagnostics.append(dict(stage='sections', reason='Overlapping raw sections'))
            if size:
                raw_ranges.append((start, start + size))
            payload = data[start:start + size]
            flags = section.Characteristics
            permissions = ''.join(letter if flags & mask else '-' for letter, mask in
                                  [('R', 0x40000000), ('W', 0x80000000), ('X', 0x20000000)])
            name = text(section.Name.rstrip(b'\0'))
            item = dict(name=name, rva=section.VirtualAddress, virtualSize=section.Misc_VirtualSize,
                        offset=start, size=size, permissions=permissions, entropy=entropy(payload),
                        sha256=hashlib.sha256(payload).hexdigest())
            sections.append(item)
            if permissions == 'RWX':
                context.finding('native.section.rwx', ['Section is writable and executable'],
                                [dict(section=name, rva=section.VirtualAddress)], 100, 'medium',
                                limitations=['RWX permissions alone do not establish malicious behavior or packing.'])
            if size >= 1024 and item['entropy'] >= 7.2:
                context.finding('native.section.entropy', ['Shannon entropy >= 7.2 bits/byte'],
                                [dict(section=name, rva=section.VirtualAddress)], 60, 'low',
                                limitations=['Compressed resources and encrypted data can be legitimate.'])
        def rva_offset(rva, size):
            if rva < 0:
                raise ValueError('Negative RVA')
            candidates = []
            if rva < pe.OPTIONAL_HEADER.SizeOfHeaders and rva + size <= min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(data)):
                candidates.append(rva)
            for section in sections:
                delta = rva - section['rva']
                if 0 <= delta and delta + size <= section['size']:
                    candidates.append(section['offset'] + delta)
            if len(candidates) != 1:
                raise ValueError('RVA has no unique file-backed range')
            return candidates[0]
        pe.parse_data_directories(directories=[0, 1, 9, 13])
        imports = []
        for attribute, delayed in [('DIRECTORY_ENTRY_IMPORT', False), ('DIRECTORY_ENTRY_DELAY_IMPORT', True)]:
            for descriptor in getattr(pe, attribute, []):
                imports.append(dict(library=text(descriptor.dll), delayed=delayed,
                                    symbols=[dict(name=text(symbol.name), ordinal=symbol.ordinal,
                                                  address=symbol.address) for symbol in descriptor.imports]))
        exports = [dict(name=text(symbol.name), ordinal=symbol.ordinal, rva=symbol.address,
                        forwarder=text(symbol.forwarder))
                   for symbol in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])]
        callbacks = []
        tls = getattr(pe, 'DIRECTORY_ENTRY_TLS', None)
        if tls and tls.struct.AddressOfCallBacks:
            pointer_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20b else 4
            rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            try:
                for index in range(1024):
                    offset = rva_offset(rva + pointer_size * index, pointer_size)
                    address = int.from_bytes(data[offset:offset + pointer_size], 'little')
                    if not address:
                        break
                    callbacks.append(dict(va=address, rva=address - pe.OPTIONAL_HEADER.ImageBase))
                else:
                    raise ValueError('TLS callback budget exceeded')
            except ValueError as error:
                diagnostics.append(dict(stage='tls', reason=str(error)))
        end = max([min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(data))] +
                  [section['offset'] + section['size'] for section in sections if section['size']])
        overlay = dict(offset=end, size=len(data) - end, sha256=hashlib.sha256(data[end:]).hexdigest())
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        certificate = dict(present=False, verified=False)
        if len(directory) > 4 and directory[4].Size:
            offset, size = directory[4].VirtualAddress, directory[4].Size
            certificate.update(present=True, offset=offset, size=size)
            if offset > len(data) or size > len(data) - offset:
                diagnostics.append(dict(stage='certificate', reason='Certificate range exceeds file'))
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry and not any(s['rva'] <= entry < s['rva'] + max(s['virtualSize'], s['size']) and 'X' in s['permissions'] for s in sections):
            context.finding('native.entry-point', ['Entry point is outside executable sections'],
                            [dict(rva=entry)], 90, 'medium')
        extracted, truncated = strings(data) if context.mode != 'inspect' else ([], False)
        for warning in pe.get_warnings():
            if 'Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE' in warning:
                continue  # Already represented as an evidence-based finding.
            diagnostics.append(dict(stage='pefile', reason=warning))
        metadata = dict(format='PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20b else 'PE32',
                        architecture={0x14c: 'I386', 0x8664: 'AMD64', 0xaa64: 'ARM64'}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
                        subsystem=pe.OPTIONAL_HEADER.Subsystem, imageBase=pe.OPTIONAL_HEADER.ImageBase,
                        entryPoint=entry, timestamp=pe.FILE_HEADER.TimeDateStamp,
                        sections=sections, imports=imports, exports=exports, tlsCallbacks=callbacks,
                        overlay=overlay, certificate=certificate, strings=extracted, stringsTruncated=truncated,
                        dataDirectories=[dict(index=i, address=d.VirtualAddress, size=d.Size,
                                              addressKind='file-offset' if i == 4 else 'RVA') for i, d in enumerate(directory)])
        try:
            entry_offset = rva_offset(entry, 10)
            entry_bytes = data[entry_offset:entry_offset + 10]
        except ValueError:
            entry_bytes = b''
        metadata['protection'] = detect_vmprotect(metadata, entry_bytes)
        if metadata['protection']:
            protection = metadata['protection']
            context.finding('native.protection.vmprotect',
                            [e['detail'] for e in protection['evidence']],
                            [dict(rva=entry)], protection['confidence'], 'info',
                            limitations=protection['limitations'])
        return context.report(metadata, plan=unpack_plan(metadata), limitations=[
            'Read-only PE analysis; executable code and TLS callbacks are never invoked.',
            'Authenticode presence is reported without cryptographic trust verification.',
            'Overlay includes any certificate table after the last section.',
            'Strings: ASCII and ASCII-range UTF-16LE, at most 10000 values, 2048 bytes per value.',
            'Resources, relocations, debug and unwind directories are inventoried but not decoded.',
            'ELF, disassembly, CFG and native rewriting belong to later milestones.'])
