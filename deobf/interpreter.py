"""Bounded static interpreter. No target class loading and no arbitrary API calls."""
from .classfile import literal, descriptor
from .values import Value as V, Unresolved, arithmetic, arity, wrap
from .crypto import Object, call, string, raw, byte_array, LIMIT


class Interpreter:
    def __init__(self, classes, pools=None, steps=100000):
        self.classes={c.name:c for c in classes.values()}
        self.methods={(c.name,m.name,m.desc):m for c in classes.values() for m in c.methods}
        self.pools=pools or {}
        self.steps=steps
        self.events=[]
        self.writes={}
        self.remaining=steps

    def run(self, owner, method, args=(), depth=0, initializer=False):
        if depth==0: self.remaining=self.steps; self.events=[]; self.writes={}
        if depth>12: raise Unresolved('Interpreter recursion budget exceeded')
        if not method.access&8: raise Unresolved('Only static target methods are modeled')
        if method.access&0x120: raise Unresolved('Native/synchronized method')
        locals_,stack={},[]
        types,_=descriptor(method.desc); slot=0
        if len(types)!=len(args): raise Unresolved('Argument count mismatch')
        for t,v in zip(types,args): locals_[slot]=v; slot+=2 if t in ('J','D') else 1
        offsets={i.offset:p for p,i in enumerate(method.insns)}
        p=0
        while p<len(method.insns):
            self.remaining-=1
            if self.remaining<0: raise Unresolved('Interpreter instruction budget exceeded')
            i=method.insns[p]; op=i.op; p+=1
            def pop():
                if not stack: raise Unresolved('Unknown/empty operand stack')
                return stack.pop()
            def jump(off):
                if off not in offsets: raise Unresolved('Invalid branch target')
                return offsets[off]
            const=literal(i)
            if const is not None: stack.append(V(*const)); continue
            n=arity(op)
            if n:
                a=[pop() for _ in range(n)][::-1]; stack.append(arithmetic(op,a)); continue
            if op==0: continue
            if 21<=op<=25:
                if i.arg not in locals_: raise Unresolved('Uninitialized local')
                stack.append(locals_[i.arg])
            elif 54<=op<=58: locals_[i.arg]=pop()
            elif op==132:
                index,delta=i.arg; v=locals_.get(index)
                if v is None or v.kind!='I': raise Unresolved('Unknown iinc local')
                locals_[index]=V('I',wrap(v.value+delta,32))
            elif op==87:
                if pop().kind in ('J','D'): raise Unresolved('Invalid POP')
            elif op==88:
                if pop().kind not in ('J','D'):
                    if pop().kind in ('J','D'): raise Unresolved('Invalid POP2')
            elif op==89:
                v=pop()
                if v.kind in ('J','D'): raise Unresolved('Invalid DUP')
                stack.extend((v,v))
            elif op==90:
                a,b=pop(),pop()
                if a.kind in ('J','D') or b.kind in ('J','D'): raise Unresolved('Invalid DUP_X1')
                stack.extend((a,b,a))
            elif op==92:
                a=pop()
                if a.kind in ('J','D'): stack.extend((a,a))
                else:
                    b=pop()
                    if b.kind in ('J','D'): raise Unresolved('Invalid DUP2')
                    stack.extend((b,a,b,a))
            elif op==95:
                a,b=pop(),pop()
                if a.kind in ('J','D') or b.kind in ('J','D'): raise Unresolved('Invalid SWAP')
                stack.extend((a,b))
            elif op in (188,189):
                count=pop()
                if count.kind!='I' or not 0<=count.value<=LIMIT: raise Unresolved('Array allocation budget/type')
                if op==189 and i.arg not in ('java/lang/String','Ljava/lang/String;','java/lang/Object'): raise Unresolved('Unsupported array element class')
                default=V('N',None) if op==189 else V('J' if i.arg==11 else 'F' if i.arg==6 else 'D' if i.arg==7 else 'I',0)
                stack.append(V('A',[V(default.kind,default.value) for _ in range(count.value)]))
            elif 46<=op<=53:
                index,arr=pop(),pop()
                if index.kind!='I': raise Unresolved('Non-integer array index')
                a=arr.value if arr.kind=='A' else [V('I',wrap(x,8)) for x in raw(arr)]
                if not 0<=index.value<len(a): raise Unresolved('Array index out of bounds')
                stack.append(a[index.value])
            elif 79<=op<=86:
                v,index,arr=pop(),pop(),pop()
                if index.kind!='I' or arr.kind!='A' or not 0<=index.value<len(arr.value): raise Unresolved('Array store invalid')
                if op==84: v=V('I',wrap(v.value,8))
                elif op==85: v=V('I',v.value&65535)
                elif op==86: v=V('I',wrap(v.value,16))
                arr.value[index.value]=v
            elif op==190:
                a=pop(); stack.append(V('I',len(a.value) if a.kind=='A' else len(raw(a))))
            elif op==178:
                ref=i.arg; o,n,d=ref
                if o=='java/nio/charset/StandardCharsets' and d=='Ljava/nio/charset/Charset;':
                    names={'UTF_8':'UTF-8','UTF_16':'UTF-16','UTF_16BE':'UTF-16BE','UTF_16LE':'UTF-16LE','US_ASCII':'US-ASCII','ISO_8859_1':'ISO-8859-1'}
                    if n not in names: raise Unresolved('Unknown StandardCharsets field')
                    v=V('O',Object('charset',{'name':names[n]}))
                elif ref in self.writes: v=self.writes[ref]
                elif ref in self.pools: v=V('A',[V('S',x) if x is not None else V('N',None) for x in self.pools[ref]])
                else:
                    c=self.classes.get(o); fs=[f for f in c.fields if f[1:3]==(n,d) and f[0]&0x18==0x18] if c else []
                    if len(fs)!=1 or fs[0][3] is None: raise Unresolved('Unknown static field: '+o+'.'+n)
                    v=V(*fs[0][3])
                stack.append(v)
            elif op==179:
                if not initializer or i.arg[0]!=owner: raise Unresolved('Static write outside analyzed initializer')
                self.writes[i.arg]=pop()
            elif op==187:
                if i.arg not in ('java/lang/String','java/lang/StringBuilder','javax/crypto/spec/SecretKeySpec','javax/crypto/spec/IvParameterSpec'):
                    raise Unresolved('Allocation not allowlisted: '+i.arg)
                stack.append(V('O',Object(i.arg)))
            elif op in (182,183,184,185):
                o,n,d=i.arg; types,ret=descriptor(d)
                params=[pop() for _ in types][::-1]; receiver=None if op==184 else pop()
                if op==184 and i.arg in self.methods:
                    if o!=owner: raise Unresolved('Cross-class helper initialization is unknown')
                    result=self.run(o,self.methods[i.arg],params,depth+1,initializer=False)
                else: result=call(o,n,d,receiver,params,self.events)
                if ret!='V':
                    if result is None: raise Unresolved('Missing API result')
                    stack.append(result)
            elif 153<=op<=158:
                v=pop()
                if v.kind!='I': raise Unresolved('Non-integer branch')
                take=(v.value==0,v.value!=0,v.value<0,v.value>=0,v.value>0,v.value<=0)[op-153]
                if take: p=jump(i.arg)
            elif 159<=op<=164:
                b,a=pop(),pop()
                if a.kind!='I' or b.kind!='I': raise Unresolved('Non-integer branch')
                x,y=a.value,b.value
                if (x==y,x!=y,x<y,x>=y,x>y,x<=y)[op-159]: p=jump(i.arg)
            elif op in (165,166):
                b,a=pop(),pop()
                if a.kind=='N' or b.kind=='N': eq=a.kind==b.kind
                elif a.kind in ('A','O') and b.kind in ('A','O'): eq=a.value is b.value
                else: raise Unresolved('String identity branch is not modeled')
                if eq==(op==165): p=jump(i.arg)
            elif op==167: p=jump(i.arg)
            elif op in (170,171):
                v=pop()
                if v.kind!='I': raise Unresolved('Unknown switch key')
                default,pairs=i.arg; p=jump(pairs.get(v.value,default))
            elif op in (198,199):
                v=pop()
                if (v.kind=='N')==(op==198): p=jump(i.arg)
            elif op==192:
                v=pop()
                if v.kind=='N' or (i.arg=='java/lang/String' and v.kind=='S'): stack.append(v)
                else: raise Unresolved('Unsupported cast')
            elif 172<=op<=176:
                v=pop()
                if op==176 and v.kind=='O' and v.value.type=='java/lang/String': v=V('S',string(v))
                return v
            elif op==177: return None
            else: raise Unresolved('Bytecode not allowlisted: opcode '+str(op)+' at '+str(i.offset))
            if len(stack)>65535: raise Unresolved('Stack budget exceeded')
        raise Unresolved('No deterministic return')
