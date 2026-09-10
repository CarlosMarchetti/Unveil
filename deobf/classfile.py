"""Read-only class-file decoder. Unknown attributes are kept in the original bytes.

Rewriting is exclusively delegated to ASM; instruction ordinals count real
instructions, not labels/frames/debug nodes. Offsets remain available for reports.
"""
import struct
from dataclasses import dataclass, field


class ClassError(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data, self.p = data, 0

    def take(self, n):
        if n < 0 or self.p + n > len(self.data):
            raise ClassError('Truncated class file')
        b = self.data[self.p:self.p+n]
        self.p += n
        return b

    def u1(self): return self.take(1)[0]
    def u2(self): return int.from_bytes(self.take(2), 'big')
    def u4(self): return int.from_bytes(self.take(4), 'big')


def mutf8(b):
    # JVM modified UTF-8 encodes NUL and UTF-16 surrogate pairs separately.
    s = b.replace(b'\xc0\x80', b'\x00').decode('utf-8', 'surrogatepass')
    return s.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')


@dataclass
class Insn:
    op: int
    arg: object
    offset: int
    start: int
    end: int
    boundary: bool = False


@dataclass
class Method:
    access: int
    name: str
    desc: str
    insns: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    max_locals: int = 0


def descriptor(desc):
    def one(p):
        start = p
        while desc[p] == '[': p += 1
        if desc[p] == 'L': p = desc.index(';', p) + 1
        else: p += 1
        return desc[start:p], p
    args, p = [], 1
    while desc[p] != ')':
        a, p = one(p)
        args.append(a)
    return args, desc[p+1:]


class ClassFile:
    def __init__(self, data, entry=''):
        self.data, self.entry = data, entry
        self.invalid_signatures=set()
        self.invalid_annotations=set()
        r = Reader(data)
        if r.u4() != 0xcafebabe: raise ClassError('Invalid class magic')
        self.minor, self.major = r.u2(), r.u2()
        self.cp = [None] * r.u2()
        i = 1
        while i < len(self.cp):
            t = r.u1()
            if t == 1: v = mutf8(r.take(r.u2()))
            elif t in (3, 4): v = struct.unpack('>i' if t == 3 else '>f', r.take(4))[0]
            elif t in (5, 6): v = struct.unpack('>q' if t == 5 else '>d', r.take(8))[0]
            elif t in (7, 8, 16, 19, 20): v = r.u2()
            elif t in (9, 10, 11, 12, 17, 18): v = (r.u2(), r.u2())
            elif t == 15: v = (r.u1(), r.u2())
            else: raise ClassError('Unsupported constant-pool tag %d' % t)
            self.cp[i] = (t, v)
            i += 2 if t in (5, 6) else 1
        self.access = r.u2()
        self.name, self.super = self.cls(r.u2()), self.cls(r.u2())
        self.interfaces = [self.cls(r.u2()) for _ in range(r.u2())]
        self.fields = []
        for _ in range(r.u2()):
            a, n, d = r.u2(), self.utf(r.u2()), self.utf(r.u2())
            attrs = self.attrs(r)
            cv = attrs.get('ConstantValue')
            self.fields.append((a, n, d, self.const(int.from_bytes(cv, 'big')) if cv else None))
        self.methods = []
        for _ in range(r.u2()):
            m = Method(r.u2(), self.utf(r.u2()), self.utf(r.u2()))
            attrs = self.attrs(r)
            if 'Code' in attrs: self.code(m, attrs['Code'])
            self.methods.append(m)
        self.attrs(r)
        if r.p != len(data): raise ClassError('Trailing class bytes')

    def utf(self, i):
        if not i or self.cp[i][0] != 1: raise ClassError('Expected UTF8')
        return self.cp[i][1]

    def cls(self, i): return self.utf(self.cp[i][1]) if i else None

    def ref(self, i):
        t, (owner, nt) = self.cp[i]
        if t not in (9, 10, 11): raise ClassError('Expected member reference')
        n, d = self.cp[nt][1]
        return self.cls(owner), self.utf(n), self.utf(d)

    def const(self, i):
        t, v = self.cp[i]
        if t in (3, 4, 5, 6): return ({3:'I',4:'F',5:'J',6:'D'}[t], v)
        if t == 8: return ('S', self.utf(v))
        return ('unknown', i)

    def attrs(self, r):
        out = {}
        for _ in range(r.u2()):
            name, size = self.utf(r.u2()), r.u4()
            out[name] = r.take(size)
            if name=='Signature':
                s=self.utf(int.from_bytes(out[name],'big'))
                if not s or s[0] not in '(<LT[': self.invalid_signatures.add(s)
            elif name=='RuntimeInvisibleAnnotations':
                q=Reader(out[name])
                def annotation(depth=0):
                    if depth>64: raise ClassError('Annotation nesting limit')
                    d=self.utf(q.u2())
                    if not (d.startswith('L') and d.endswith(';') and len(d)>2): self.invalid_annotations.add(d)
                    for _ in range(q.u2()): q.u2(); element(depth+1)
                def element(depth):
                    t=chr(q.u1())
                    if t in 'BCDFIJSZsc': q.u2()
                    elif t=='e': q.u2(); q.u2()
                    elif t=='@': annotation(depth)
                    elif t=='[':
                        if depth>64: raise ClassError('Annotation nesting limit')
                        for _ in range(q.u2()): element(depth+1)
                    else: raise ClassError('Invalid annotation element')
                for _ in range(q.u2()): annotation()
        return out

    def code(self, m, data):
        r = Reader(data)
        r.u2()
        m.max_locals = r.u2()
        code = r.take(r.u4())
        bounds = {0}
        for _ in range(r.u2()):
            a, b, h, t = r.u2(), r.u2(), r.u2(), r.u2()
            m.handlers.append((a,b,h,self.cls(t)))
            bounds.update((a,b,h))
        attrs = self.attrs(r)
        # Every StackMapTable frame is also a hard expression boundary.
        if 'StackMapTable' in attrs:
            q, off = Reader(attrs['StackMapTable']), -1
            def vt():
                t = q.u1()
                if t in (7,8): q.u2()
            for _ in range(q.u2()):
                t = q.u1()
                if t < 64: delta = t
                elif t < 128: delta = t-64; vt()
                elif t == 247: delta = q.u2(); vt()
                elif 248 <= t <= 251: delta = q.u2()
                elif 252 <= t <= 254:
                    delta = q.u2()
                    for _ in range(t-251): vt()
                elif t == 255:
                    delta = q.u2()
                    for _ in range(q.u2()): vt()
                    for _ in range(q.u2()): vt()
                else: raise ClassError('Invalid StackMapTable')
                off += delta+1
                bounds.add(off)
        q = Reader(code)
        while q.p < len(code):
            off, op, arg = q.p, q.u1(), None
            if op == 16: arg = int.from_bytes(q.take(1), 'big', signed=True)
            elif op == 17: arg = int.from_bytes(q.take(2), 'big', signed=True)
            elif op in (18,19,20): arg = self.const(q.u1() if op == 18 else q.u2()); op = 18
            elif op in range(21,26) or op in range(54,59) or op in (169,188): arg = q.u1()
            elif 26 <= op <= 45: arg, op = (op-26)%4, 21+(op-26)//4
            elif 59 <= op <= 78: arg, op = (op-59)%4, 54+(op-59)//4
            elif op == 132: arg = (q.u1(), int.from_bytes(q.take(1),'big',signed=True))
            elif 153 <= op <= 168 or op in (198,199,200,201):
                arg = off + int.from_bytes(q.take(4 if op >= 200 else 2),'big',signed=True)
                bounds.update((arg,q.p))
                if op >= 200: op -= 33
            elif op in (170,171):
                q.take((-q.p)%4)
                default = off + int.from_bytes(q.take(4),'big',signed=True)
                if op == 170:
                    low = int.from_bytes(q.take(4),'big',signed=True)
                    high = int.from_bytes(q.take(4),'big',signed=True)
                    if high-low < 0 or high-low > 65535: raise ClassError('Bad switch')
                    pairs = {k:off+int.from_bytes(q.take(4),'big',signed=True) for k in range(low,high+1)}
                else:
                    count = q.u4()
                    if count > 65535: raise ClassError('Bad switch')
                    pairs = {}
                    for _ in range(count):
                        k = int.from_bytes(q.take(4),'big',signed=True)
                        pairs[k] = off+int.from_bytes(q.take(4),'big',signed=True)
                arg = (default,pairs)
                bounds.update([default,*pairs.values(),q.p])
            elif 178 <= op <= 185:
                arg = self.ref(q.u2())
                if op == 185: q.take(2)
            elif op == 186: arg = q.u2(); q.take(2)
            elif op in (187,189,192,193): arg = self.cls(q.u2())
            elif op == 197: arg = (self.cls(q.u2()),q.u1())
            elif op == 196:
                op = q.u1()
                if op == 132: arg = (q.u2(),int.from_bytes(q.take(2),'big',signed=True))
                elif op in (*range(21,26),*range(54,59),169): arg = q.u2()
                else: raise ClassError('Bad wide opcode')
            elif op > 201: raise ClassError('Reserved opcode')
            idx = len(m.insns)
            m.insns.append(Insn(op,arg,off,idx,idx+1))
        for ins in m.insns: ins.boundary = ins.offset in bounds


def literal(i):
    if i.op == 1: return ('N',None)
    if 2 <= i.op <= 8: return ('I',i.op-3)
    if i.op in (9,10): return ('J',i.op-9)
    if 11 <= i.op <= 13: return ('F',float(i.op-11))
    if i.op in (14,15): return ('D',float(i.op-14))
    if i.op in (16,17): return ('I',i.arg)
    if i.op == 18 and i.arg[0] != 'unknown': return i.arg
    return None
