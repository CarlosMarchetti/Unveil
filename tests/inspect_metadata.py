import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deobf.classfile import ClassFile,Reader
import zipfile,collections
z=zipfile.ZipFile(sys.argv[1])
for n in ['liliillIiIlIIIliiiIliIIIIilllilI.class','iiilillIIlIIIiIilliiIiIIiilillIl.class','generated/Strings0.class']:
    seen=collections.defaultdict(list)
    class Inspect(ClassFile):
        def attrs(self,r):
            attrs=super().attrs(r)
            for k,b in attrs.items():
                if k=='Signature': seen[k].append(self.utf(int.from_bytes(b,'big'))[:80])
                if 'Annotation' in k:
                    q=Reader(b)
                    try: count=q.u2(); seen[k].append((count,self.utf(q.u2())[:80] if count else ''))
                    except Exception as e: seen[k].append(str(e))
            return attrs
    c=Inspect(z.read(n),n)
    print(n,{k:v[:5] for k,v in seen.items()})
    if n.startswith('generated'):
        print(c.fields,[(i.op,i.arg) for i in c.methods[0].insns[:12]])
