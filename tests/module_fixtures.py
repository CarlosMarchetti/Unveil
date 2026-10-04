"""Authored DLLs and launcher code, executed only inside Unicorn tests."""
import struct

from framework_fixtures import pe_bytes
from test_unpack import packed_fixture


def dll_bytes(name='fixture.dll', symbol='answer', ordinal=1, forwarder=None,
              dependency=None, delay_dependency=None):
    data = bytearray(pe_bytes()[:0xa00])
    base = 0x140000000
    directories = 0x98 + 112
    data[directories:directories + 128] = bytes(128)
    struct.pack_into('<I', data, 0x98 + 16, 0)
    data[0x200:] = bytes(0x800)
    data[0x200:0x206] = b'\xb8\x2a\0\0\0\xc3'

    def at(rva):
        return rva - 0x1000 + 0x200

    struct.pack_into('<II', data, directories, 0x1200, 0x100)
    struct.pack_into('<IIHHIIIIIII', data, at(0x1200), 0, 0, 0, 0,
                     0x1250, ordinal, 1, 1, 0x1260, 0x1270, 0x1280)
    encoded = name.encode() + b'\0'
    data[at(0x1250):at(0x1250) + len(encoded)] = encoded
    struct.pack_into('<I', data, at(0x1260), 0x12c0 if forwarder else 0x1000)
    struct.pack_into('<I', data, at(0x1270), 0x1290)
    struct.pack_into('<H', data, at(0x1280), 0)
    encoded = symbol.encode() + b'\0'
    data[at(0x1290):at(0x1290) + len(encoded)] = encoded
    if forwarder:
        encoded = forwarder.encode() + b'\0'
        data[at(0x12c0):at(0x12c0) + len(encoded)] = encoded
    struct.pack_into('<Q', data, at(0x1400), base + 0x1000)
    struct.pack_into('<II', data, directories + 5 * 8, 0x1500, 12)
    struct.pack_into('<IIHH', data, at(0x1500), 0x1000, 12, 0xa400, 0)
    for dll, rva, index in [(dependency, 0x1600, 1), (delay_dependency, 0x1700, 13)]:
        if dll is None:
            continue
        name_rva, lookup, iat, import_name = rva + 0x80, rva + 0x60, rva + 0x70, rva + 0xa0
        struct.pack_into('<II', data, directories + index * 8, rva, 64 if index == 13 else 40)
        if index == 13:
            struct.pack_into('<IIIIIIII', data, at(rva), 1, name_rva, 0, iat, lookup, 0, 0, 0)
        else:
            struct.pack_into('<IIIII', data, at(rva), lookup, 0, 0, name_rva, iat)
        struct.pack_into('<Q', data, at(lookup), import_name)
        struct.pack_into('<Q', data, at(iat), import_name)
        encoded = dll.encode() + b'\0'
        data[at(name_rva):at(name_rva) + len(encoded)] = encoded
        data[at(import_name) + 2:at(import_name) + 9] = b'answer\0'
    return bytes(data)


def module_launcher(*, wide=False, ordinal=False, load=False, main=False, main_lookup=False):
    code = bytearray()

    def lea(reg, target):
        code.extend(b'\x48\x8d' + bytes([reg]) + struct.pack('<i', target - (0x4000 + len(code) + 7)))

    def call(target):
        code.extend(b'\xff\x15' + struct.pack('<i', target - (0x4000 + len(code) + 6)))

    if main and not main_lookup:
        code.extend(b'\x31\xc9')
    else:
        lea(0x0d, 0x4900)
    call(0x4860)
    code.extend(b'\x48\x89\xc1')
    if ordinal:
        code.extend(b'\xba\x01\0\0\0')
    else:
        lea(0x15, 0x4940)
    call(0x4868)
    code.extend(b'\xff\xd0')
    code.extend(b'\x89\x05' + struct.pack('<i', 0x2000 - (0x4000 + len(code) + 6)))
    code.extend(b'\xc6\x05' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 7)) + b'\xc3')
    code.extend(b'\xe9' + struct.pack('<i', 0x1000 - (0x4000 + len(code) + 5)))
    data = bytearray(packed_fixture(bytes(code)))
    struct.pack_into('<II', data, 0x98 + 112 + 8, 0x4800, 40)
    data[0xc00:0xea0] = bytes(0x2a0)
    struct.pack_into('<IIIII', data, 0xc00, 0x4840, 0, 0, 0x4880, 0x4860)
    struct.pack_into('<QQQ', data, 0xc40, 0x48a0, 0x48c0, 0)
    struct.pack_into('<QQQ', data, 0xc60, 0x48a0, 0x48c0, 0)
    data[0xc80:0xc8d] = b'KERNEL32.dll\0'
    api = ('LoadLibrary' if load else 'GetModuleHandle') + ('W' if wide else 'A')
    encoded = api.encode() + b'\0'
    data[0xca2:0xca2 + len(encoded)] = encoded
    data[0xcc2:0xcc2 + 15] = b'GetProcAddress\0'
    encoded = ('sample.exe\0' if main else 'kernel32.dll\0').encode('utf-16le' if wide else 'ascii')
    data[0xd00:0xd00 + len(encoded)] = encoded
    data[0xd40:0xd47] = b'answer\0'
    if main:
        struct.pack_into('<II', data, 0x98 + 112, 0x4a00, 0x100)
        # Place a tiny export directory in the backed launcher section.
        exported = dll_bytes()
        data[0xe00:0xf00] = exported[0x400:0x500]
        fields = list(struct.unpack_from('<IIHHIIIIIII', data, 0xe00))
        for index in (4, 8, 9, 10):
            fields[index] += 0x3800
        struct.pack_into('<IIHHIIIIIII', data, 0xe00, *fields)
        struct.pack_into('<I', data, 0xe60, 0x4b00)
        struct.pack_into('<I', data, 0xe70, 0x4a90)
        data[0xf00:0xf06] = b'\xb8\x2a\0\0\0\xc3'
    return bytes(data)
