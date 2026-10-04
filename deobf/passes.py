"""Transformation planning in Python; the helper contains no detection logic."""
from collections import Counter, defaultdict
from .classfile import literal, descriptor, Insn
from .values import Value as V, Unresolved, arithmetic, arity
from .interpreter import Interpreter
from .crypto import call, string


def edit(m, first, last, replacement, **meta):
    return dict(method=m.name,desc=m.desc,start=first.start,end=last.end,
                replacement=replacement,offset=first.offset,**meta)


def constants(classes):
    plans={}
    for entry,c in classes.items():
        edits=[]
        for m in c.methods:
            out=[]; counts={}
            for i in m.insns:
                n=arity(i.op)
                if n and len(out)>=n and not i.boundary:
                    operands=out[-n:]
                    vals=[literal(x) for x in operands]
                    if all(x is not None for x in vals) and not any(x.boundary for x in operands[1:]):
                        try: v=arithmetic(i.op,[V(*x) for x in vals])
                        except (Unresolved,ValueError,OverflowError): pass
                        else:
                            first=operands[0]; total=Counter({v.kind:1})
                            for x in operands: total.update(counts.pop(x.start,{}))
                            counts[first.start]=total
                            out[-n:]=[Insn(18,v.pair(),first.offset,first.start,i.end,first.boundary)]
                            continue
                out.append(i)
            for i in out:
                if i.start in counts:
                    edits.append(edit(m,i,i,[i.arg],passName='ConstantDeobf',counts=dict(counts[i.start])))
        if edits: plans[entry]=edits
    return plans


def metadata_cleanup(classes):
    plans={}
    for entry,c in classes.items():
        edits=[]
        for kind,values in [('signature',c.invalid_signatures),('invisible-annotation',c.invalid_annotations)]:
            for value in values:
                edits.append(dict(method='@metadata',desc=kind,start=-1,end=-1,replacement=[('S',value)],passName='MetadataCleanup'))
        if edits: plans[entry]=edits
    return plans


def discover_pools(classes):
    vm=Interpreter(classes); pools={}; details=[]; verified_initializers=set()
    # Evaluate whole deterministic clinit only. Arbitrary initializers are not run.
    for c in classes.values():
        if c.super!='java/lang/Object' or c.interfaces: continue
        fields={(c.name,n,d) for a,n,d,_ in c.fields if a&8 and d=='[Ljava/lang/String;'}
        if not fields: continue
        m=next((m for m in c.methods if m.name=='<clinit>'),None)
        if m is None: continue
        try:
            vm.run(c.name,m,initializer=True)
            for ref in fields:
                a=vm.writes.get(ref)
                if a is None or a.kind!='A': continue
                if any(other not in fields and value.kind=='A' and value.value is a.value for other,value in vm.writes.items()): continue
                strings=[string(v) if v.kind!='N' else None for v in a.value]
                pools[ref]=strings
                verified_initializers.add((c.name,m.name,m.desc))
        except (Unresolved,ValueError,KeyError,IndexError,TypeError,OverflowError): continue
    # Closed-world escape/mutation audit. No field reassignment outside the
    # initializer, no array aliases/calls/returns, no handles referring to field.
    rejected={}
    for c in classes.values():
        for cp in c.cp:
            if cp and cp[0]==15:
                try:
                    ref=c.ref(cp[1][1])
                    if ref in pools: rejected[ref]='field referenced by method handle'
                except (ValueError,TypeError): pass
        for m in c.methods:
            for p,i in enumerate(m.insns):
                if i.op not in (178,179) or i.arg not in pools: continue
                if (c.name,m.name,m.desc) in verified_initializers and i.op==179: continue
                if i.op==179: rejected[i.arg]='field reassigned outside deterministic clinit'; continue
                rest=m.insns[p+1:p+129]
                index_stack=[]; read_only=False
                for x in rest:
                    v=literal(x); n=arity(x.op)
                    if v is not None: index_stack.append(V(*v))
                    elif n and len(index_stack)>=n:
                        try: v=arithmetic(x.op,index_stack[-n:]); del index_stack[-n:]; index_stack.append(v)
                        except (Unresolved,ValueError,OverflowError): break
                    elif x.op==50:
                        read_only=len(index_stack)==1 and index_stack[0].kind=='I'; break
                    else: break
                if read_only: continue
                if rest and rest[0].op==87: continue
                rejected[i.arg]='array escapes or index is not constant'
    for ref,vals in list(pools.items()):
        details.append({'owner':ref[0],'field':ref[1],'descriptor':ref[2],'size':len(vals),
                        'resolved':sum(s is not None for s in vals),'accepted':ref not in rejected,
                        'reason':rejected.get(ref),'assumption':'closed-world field usage; external reflection/JNI mutation not modeled'})
        if ref in rejected: del pools[ref]
    return pools,details


def pool_uses(classes,pools):
    plans={}
    for entry,c in classes.items():
        edits=[]
        for m in c.methods:
            ins=m.insns; p=0
            while p+2<len(ins):
                a,b,z=ins[p:p+3]; v=literal(b)
                if a.op==178 and a.arg in pools and v is not None and v[0]=='I' and z.op==50 and not b.boundary and not z.boundary:
                    values=pools[a.arg]; index=v[1]
                    if 0<=index<len(values):
                        s=values[index]
                        # Discovered pools have fully deterministic initialization.
                        edits.append(edit(m,a,z,[('N',None) if s is None else ('S',s)],passName='StringPoolerDeobf',pool=a.arg[0],index=index))
                        p+=3; continue
                p+=1
        if edits: plans[entry]=edits
    return plans


def candidates(classes):
    result={}
    for c in classes.values():
        for m in c.methods:
            if not m.access&8 or not m.desc.endswith(')Ljava/lang/String;'): continue
            calls={(i.arg[0],i.arg[1]) for i in m.insns if i.op in (182,183,184,185)}
            base=('java/util/Base64$Decoder','decode') in calls
            cipher=('javax/crypto/Cipher','doFinal') in calls
            xor=any(i.op==130 for i in m.insns) and ('java/lang/String','toCharArray') in calls
            if not (cipher or xor): continue
            indicators=[o+'.'+n for o,n in sorted(calls) if o.startswith(('javax/crypto/','java/security/MessageDigest','java/util/Base64'))]
            if xor: indicators+=['IXOR','String.toCharArray']
            result[(c.name,m.name,m.desc)]={'owner':c.name,'method':m.name,'descriptor':m.desc,
                'confidence':min(1.0,0.85+0.02*(len(indicators)-2)) if cipher else 0.8,
                'indicators':indicators,'confirmed':False,'kind':'cipher' if cipher else 'base64-xor' if base else 'xor'}
    return result


def decrypt(classes, found, pools):
    vm=Interpreter(classes,pools); plans={}; unresolved=[]; cache={}
    for entry,c in classes.items():
        edits=[]
        for m in c.methods:
            # A conservative block interpreter for call-site arguments. Local
            # values are propagated only within straight-line basic blocks.
            # Unsupported effects invalidate the stack AND locals.
            stack=[]; locals_={}
            for p,i in enumerate(m.insns):
                if i.boundary: stack=[]; locals_={}
                v=literal(i)
                if v is not None: stack.append((V(*v),p,p)); continue
                n=arity(i.op)
                if n:
                    try:
                        args=stack[-n:]
                        if len(args)!=n: raise Unresolved('Unknown arithmetic arguments')
                        value=arithmetic(i.op,[v[0] for v in args]); del stack[-n:]
                        stack.append((value,args[0][1],p))
                    except (Unresolved,ValueError,OverflowError): stack=[]
                    continue
                if 54<=i.op<=58:
                    locals_[i.arg]=stack.pop()[0] if stack else None
                    continue
                if 21<=i.op<=25:
                    value=locals_.get(i.arg)
                    if value is not None: stack.append((value,p,p))
                    else: stack=[]
                    continue
                if i.op==132: locals_.pop(i.arg[0],None); continue
                if i.op in (87,88):
                    if stack:
                        value=stack.pop()[0]
                        if i.op==88 and value.kind not in ('J','D'):
                            if stack: stack.pop()
                    continue
                if i.op==184 and i.arg in found:
                    ref=i.arg; types,ret=descriptor(ref[2]); context={'class':c.name,'method':m.name+m.desc,'bytecodeOffset':i.offset,'decryptor':{'owner':ref[0],'method':ref[1],'descriptor':ref[2]}}
                    try:
                        if len(stack)<len(types): raise Unresolved('Callsite arguments are not statically known')
                        args=stack[-len(types):] if types else []
                        if not all(v[0].constant() for v in args): raise Unresolved('Nonconstant callsite arguments')
                        if ref[0]!=c.name:
                            owner=vm.classes[ref[0]]
                            init=next((x for x in owner.methods if x.name=='<clinit>'),None)
                            if init and any(x.op!=177 for x in init.insns): raise Unresolved('Cross-class initialization has effects')
                            if owner.super!='java/lang/Object' or owner.interfaces: raise Unresolved('Cross-class superclass initialization unknown')
                        key=(ref,tuple(v[0].pair() for v in args))
                        if key not in cache:
                            value=vm.run(ref[0],vm.methods[ref],[v[0] for v in args])
                            if value is None or value.kind!='S': raise Unresolved('Decryptor did not return a known String')
                            if len(value.value.encode('utf-16-be','surrogatepass'))>43000: raise Unresolved('Plaintext may exceed JVM UTF8 constant limit')
                            cache[key]=(value,list(vm.events))
                        value,events=cache[key]
                        crypto_events=[e for e in events if 'transformation' in e]
                        cipher_sources=[e['ciphertextInput'] for e in crypto_events if e.get('ciphertextInput') is not None]
                        base64_sources=[e['base64Input'] for e in events if 'base64Input' in e]
                        # Do not assume parameter zero is ciphertext: some methods
                        # receive the key first. Record only the actual decoded
                        # input that reaches Cipher, or the unique XOR decode.
                        ciphertext=cipher_sources[-1] if cipher_sources else base64_sources[0] if not crypto_events and found[ref]['kind']=='base64-xor' and len(base64_sources)==1 else None
                        # Delete the entire pure producer expression when contiguous.
                        start=args[0][1] if args else p
                        contiguous=(not args or (all(args[j][2]+1==args[j+1][1] for j in range(len(args)-1)) and args[-1][2]+1==p))
                        if contiguous and not any(x.boundary for x in m.insns[start+1:p+1]):
                            # Only producers from this tracked region, never stores.
                            pure=all(literal(x) is not None or arity(x.op) or 21<=x.op<=25 for x in m.insns[start:p])
                        else: pure=False
                        replacement=[value.pair()]
                        if not pure:
                            start=p
                            replacement=[('P',88 if t in ('J','D') else 87) for t in reversed(types)]+replacement
                        e=edit(m,m.insns[start],i,replacement,passName='StringDecrypt',decrypted={**context,
                            'ciphertext':ciphertext,
                            'plaintext':value.value,'crypto':[{k:v for k,v in event.items() if k!='ciphertextInput'} for event in crypto_events]})
                        # If a nested decrypt was planned in this same range, leave
                        # the outer call for the next iteration rather than overlap.
                        if edits and edits[-1]['method']==m.name and edits[-1]['desc']==m.desc and edits[-1]['end']>e['start']:
                            raise Unresolved('Nested expression deferred to next iteration')
                        edits.append(e)
                        if types: del stack[-len(types):]
                        stack.append((value,p,p)); found[ref]['confirmed']=True
                    except (Unresolved,ValueError,KeyError,IndexError,TypeError,OverflowError) as ex:
                        # Never include exception values from crypto/key APIs.
                        reason=str(ex) if isinstance(ex,Unresolved) else 'Safe evaluator rejected '+type(ex).__name__
                        unresolved.append({**context,'reason':reason}); stack=[]
                    continue
                if i.op in (182,183,184,185):
                    # Pure String API intermediates. Other APIs may mutate state,
                    # so do not partially evaluate them at arbitrary callsites.
                    o,name,desc=i.arg; types,ret=descriptor(desc); n=len(types)+(i.op!=184)
                    try:
                        if o!='java/lang/String' or name=='<init>' or len(stack)<n: raise Unresolved('Unknown API')
                        vals=stack[-n:] if n else []; params=[x[0] for x in vals]
                        receiver=None if i.op==184 else params.pop(0)
                        value=call(o,name,desc,receiver,params,[])
                        if n: del stack[-n:]
                        if ret!='V': stack.append((value,vals[0][1] if vals else p,p))
                    except (Unresolved,ValueError,KeyError,IndexError,TypeError): stack=[]
                    continue
                if i.op==0: continue
                stack=[]
        if edits: plans[entry]=edits
    return plans,unresolved
