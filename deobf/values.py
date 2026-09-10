"""JVM-width arithmetic. Never use Python floor division for Java integers."""
from dataclasses import dataclass
import math
import numpy as np


class Unresolved(ValueError):
    pass


@dataclass
class Value:
    kind: str
    value: object

    def constant(self): return self.kind in ('I','J','F','D','S','N')
    def pair(self): return self.kind,self.value


def wrap(v, bits): return ((int(v)+(1<<(bits-1))) % (1<<bits))-(1<<(bits-1))


def arithmetic(op, args):
    if 96 <= op <= 115:
        k='IJFD'[(op-96)%4]; operation=(op-96)//4
        a,b=args
        if a.kind!=k or b.kind!=k: raise Unresolved('Arithmetic type mismatch')
        x,y=a.value,b.value
        if k in ('I','J'):
            if operation in (3,4) and y==0: raise Unresolved('Integer division by zero')
            if operation==0: z=x+y
            elif operation==1: z=x-y
            elif operation==2: z=x*y
            else:
                q=(abs(x)//abs(y)) * (-1 if (x<0)!=(y<0) else 1)
                z=q if operation==3 else x-q*y
            return Value(k,wrap(z,32 if k=='I' else 64))
        if math.isnan(x) or math.isnan(y): raise Unresolved('NaN payload preserved')
        typ=np.float32 if k=='F' else np.float64
        with np.errstate(all='ignore'):
            x,y=typ(x),typ(y)
            z=(np.add,np.subtract,np.multiply,np.divide,np.fmod)[operation](x,y)
        if np.isnan(z): raise Unresolved('NaN result preserved')
        return Value(k,float(z))
    if 116 <= op <= 119:
        k='IJFD'[op-116]; a=args[0]
        if a.kind!=k: raise Unresolved('Negation type mismatch')
        if k in ('I','J'): return Value(k,wrap(-a.value,32 if k=='I' else 64))
        if math.isnan(a.value): raise Unresolved('NaN payload preserved')
        return Value(k,-a.value)
    if 120 <= op <= 131:
        k='I' if op%2==0 else 'J'; bits=32 if k=='I' else 64
        a,b=args; x,y=a.value,b.value
        if a.kind!=k or b.kind!=('I' if op<126 else k): raise Unresolved('Bitwise type mismatch')
        if op<126:
            y &= bits-1
            if op<122: z=x<<y
            elif op<124: z=x>>y
            else: z=(x & ((1<<bits)-1))>>y
        elif op<128: z=x&y
        elif op<130: z=x|y
        else: z=x^y
        return Value(k,wrap(z,bits))
    if 133 <= op <= 147:
        src,dst={133:('I','J'),134:('I','F'),135:('I','D'),136:('J','I'),137:('J','F'),138:('J','D'),139:('F','I'),140:('F','J'),141:('F','D'),142:('D','I'),143:('D','J'),144:('D','F'),145:('I','B'),146:('I','C'),147:('I','H')}[op]
        a=args[0]
        if a.kind!=src: raise Unresolved('Conversion type mismatch')
        x=a.value
        if dst in ('F','D'):
            with np.errstate(all='ignore'): z=float(np.float32(x)) if dst=='F' else float(x)
            return Value(dst,z)
        bits={'I':32,'J':64,'B':8,'C':16,'H':16}[dst]
        if src in ('F','D'):
            x=0 if math.isnan(x) else max(-(1<<(bits-1)),min((1<<(bits-1))-1,math.trunc(x) if math.isfinite(x) else ((1<<bits) if x>0 else -(1<<bits))))
        z=int(x)&65535 if dst=='C' else wrap(x,bits)
        return Value('J' if dst=='J' else 'I',z)
    if 148 <= op <= 152:
        a,b=[x.value for x in args]
        z=(-1 if op in (149,151) else 1) if (isinstance(a,float) and (math.isnan(a) or math.isnan(b))) else (a>b)-(a<b)
        return Value('I',z)
    raise Unresolved('Unsupported arithmetic opcode')


def arity(op):
    if 116<=op<=119 or 133<=op<=147: return 1
    if 96<=op<=131 or 148<=op<=152: return 2
    return 0
