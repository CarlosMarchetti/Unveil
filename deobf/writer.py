"""Build trusted ASM helper and exchange explicit, non-executable patch plans."""
import base64
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ('asm','asm-tree','asm-analysis','asm-util')


def build(download=True):
    lib, target = ROOT/'helper/lib', ROOT/'helper/target/classes'
    lib.mkdir(parents=True,exist_ok=True)
    target.mkdir(parents=True,exist_ok=True)
    for artifact in ARTIFACTS:
        dest = lib/(artifact+'-9.8.jar')
        if not dest.exists():
            if not download: raise RuntimeError('Missing helper dependency: '+str(dest))
            url = 'https://repo.maven.apache.org/maven2/org/ow2/asm/'+artifact+'/9.8/'+dest.name
            print('[+] Downloading trusted writer dependency '+artifact, flush=True)
            with urllib.request.urlopen(url,timeout=30) as response: data=response.read()
            with urllib.request.urlopen(url+'.sha256',timeout=30) as response: expected=response.read().decode().strip()
            if hashlib.sha256(data).hexdigest()!=expected: raise RuntimeError('Dependency hash mismatch')
            dest.write_bytes(data)
    cp = os.pathsep.join([str(target),*(str(lib/(a+'-9.8.jar')) for a in ARTIFACTS)])
    src = ROOT/'helper/src/main/java/SafeWriter.java'
    stamp=target/'build.sha256'
    digest=hashlib.sha256(src.read_bytes()).hexdigest()
    if not stamp.exists() or stamp.read_text()!=digest:
        javac=shutil.which('javac')
        if not javac: raise RuntimeError('JDK 8+ required: javac not found in PATH')
        result=subprocess.run([javac,'-encoding','UTF-8','-source','8','-target','8','-cp',cp,'-d',str(target),str(src)],capture_output=True,timeout=120)
        diagnostic=result.stderr.decode('utf-8','replace')
        # Some JDK builds return 0 after a file-manager close failure. Never
        # mark that invocation successful just because a stale .class exists.
        if result.returncode or 'exception has occurred' in diagnostic.lower() or 'AccessDeniedException' in diagnostic or not (target/'SafeWriter.class').exists():
            raise RuntimeError('Helper compilation failed: '+diagnostic[:2000])
        stamp.write_text(digest)
    java=shutil.which('java')
    if not java: raise RuntimeError('java not found in PATH')
    return java,cp


def write_plan(path, plans):
    def integer(v): f.write(struct.pack('>i',v))
    def string(v):
        b=v.encode('utf-16-be','surrogatepass'); integer(len(b)); f.write(b)
    with open(path,'wb') as f:
        integer(0x554e5631); integer(len(plans))
        for entry, edits in plans.items():
            string(entry); integer(len(edits))
            for e in edits:
                string(e['method']); string(e['desc']); integer(e['start']); integer(e['end'])
                integer(len(e['replacement']))
                for t,v in e['replacement']:
                    f.write(t.encode('ascii'))
                    if t in ('I','J','F','D'): f.write(struct.pack({'I':'>i','J':'>q','F':'>f','D':'>d'}[t],v))
                    elif t=='S': string(v)
                    elif t=='P': f.write(bytes([v]))


def invoke(runtime, mode, jar, plans, work):
    plan, out = work/'plan.bin', work/'changes.zip'
    write_plan(plan,plans)
    java, cp=runtime
    p=subprocess.run([java,'-Xmx1g','-cp',cp,'SafeWriter',mode,str(jar),str(plan),str(out)],capture_output=True,timeout=600)
    if p.returncode: raise RuntimeError('Writer failed: '+p.stderr.decode('utf-8','replace')[:2000])
    status={}
    for line in p.stdout.decode('utf-8').splitlines():
        kind, entry, why=line.split('\t')
        status[base64.b64decode(entry).decode('utf-8')]=(kind,base64.b64decode(why).decode('utf-8'))
    if set(status)!=set(plans): raise RuntimeError('Incomplete writer response')
    return out,status
