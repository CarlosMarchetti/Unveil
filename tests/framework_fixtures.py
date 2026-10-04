"""Tiny authored class/PE fixtures; PE files are data fixtures, never executed."""
import struct


def class_bytes():
    def utf(value):
        data = value.encode()
        return b'\1' + struct.pack('>H', len(data)) + data
    cp = [utf('Example'), b'\7\0\1', utf('java/lang/Object'), b'\7\0\3',
          utf('answer'), utf('()I'), utf('Code')]
    code = struct.pack('>HHI', 2, 0, 4) + b'\x04\x05\x60\xac' + b'\0\0\0\0'
    method = struct.pack('>HHHHHI', 9, 5, 6, 1, 7, len(code)) + code
    return (struct.pack('>IHHH', 0xcafebabe, 0, 52, 8) + b''.join(cp) +
            struct.pack('>HHHHHH', 0x21, 2, 4, 0, 0, 1) + method + b'\0\0')


def pe_bytes(bits=64):
    data = bytearray(0xa00)
    def put(offset, fmt, *values):
        struct.pack_into('<' + fmt, data, offset, *values)
    def at(rva):
        return rva - 0x1000 + 0x200
    data[:2] = b'MZ'
    put(60, 'I', 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional = 0xf0 if bits == 64 else 0xe0
    put(0x84, 'HHIIIHH', 0x8664 if bits == 64 else 0x14c, 1, 0, 0, 0, optional, 0x2022)
    base = 0x140000000 if bits == 64 else 0x400000
    opt = 0x98
    put(opt, 'H', 0x20b if bits == 64 else 0x10b)
    put(opt + 4, 'I', 0x800)
    put(opt + 16, 'II', 0x1000, 0x1000)
    if bits == 64:
        put(opt + 24, 'Q', base)
        put(opt + 108, 'I', 16)
        directories = opt + 112
    else:
        put(opt + 24, 'II', 0x1000, base)
        put(opt + 92, 'I', 16)
        directories = opt + 96
    put(opt + 32, 'II', 0x1000, 0x200)
    put(opt + 40, 'HHHHHH', 6, 0, 0, 0, 6, 0)
    put(opt + 56, 'II', 0x2000, 0x200)
    put(opt + 68, 'HH', 3, 0)
    section = opt + optional
    data[section:section + 8] = b'.text\0\0\0'
    put(section + 8, 'IIII', 0x800, 0x1000, 0x800, 0x200)
    put(section + 36, 'I', 0xe0000020)
    data[0x200] = 0xc3
    put(directories, 'II', 0x1200, 0x80)
    put(directories + 8, 'II', 0x1100, 40)
    put(directories + 9 * 8, 'II', 0x1300, 40 if bits == 64 else 24)
    put(at(0x1100), 'IIIII', 0x1160, 0, 0, 0x1180, 0x1170)
    pointer = 'Q' if bits == 64 else 'I'
    put(at(0x1160), pointer, 0x1190)
    put(at(0x1170), pointer, 0x1190)
    data[at(0x1180):at(0x1180) + 13] = b'KERNEL32.dll\0'
    data[at(0x1192):at(0x1192) + 12] = b'ExitProcess\0'
    put(at(0x1200), 'IIHHIIIIIII', 0, 0, 0, 0, 0x1250, 1, 1, 1, 0x1260, 0x1270, 0x1280)
    data[at(0x1250):at(0x1250) + 12] = b'fixture.dll\0'
    put(at(0x1260), 'I', 0x1000)
    put(at(0x1270), 'I', 0x1290)
    put(at(0x1280), 'H', 0)
    data[at(0x1290):at(0x1290) + 7] = b'answer\0'
    put(at(0x1300), 'QQQQII' if bits == 64 else 'IIIIII', 0, 0, base + 0x1380, base + 0x1340, 0, 0)
    put(at(0x1340), pointer, base + 0x1000)
    return bytes(data) + b'fixture-overlay'
