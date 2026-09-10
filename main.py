#!/usr/bin/env python3
"""Unveil: Python static JAR deobfuscator with a Java 8 ASM writer."""
import argparse
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import zipfile

from deobf.classfile import ClassFile
from deobf import passes
from deobf.writer import build, invoke

DEFAULT_DIR=Path(r'R:\Trabalhos\Reverse Engineering\Sunshine\Sunshine\data\.minecraft\versions\AntiHack')


def log(s):
    print(s.encode(sys.stdout.encoding or 'utf-8','backslashreplace').decode(sys.stdout.encoding or 'utf-8'),flush=True)


def clean_manifest(data):
    # Keep original bytes of all unrelated attributes, including continuations.
    lines=data.replace(b'\r\n',b'\n').replace(b'\r',b'\n').split(b'\n')
    sections=[]; fields=[]
    for line in lines+[b'']:
        if not line:
            if fields: sections.append(fields); fields=[]
        elif line.startswith(b' ') and fields: fields[-1].append(line)
        else: fields.append([line])
    result=[]
    for n,section in enumerate(sections):
        kept=[]
        for attr in section:
            name=attr[0].split(b':',1)[0].lower()
            if b'-digest' in name or name in (b'signature-version',b'magic'): continue
            kept.extend(attr)
        if n>0 and len(kept)==1 and kept[0].lower().startswith(b'name:'): continue
        if kept: result.extend(kept+[b''])
    return b'\r\n'.join(result)+b'\r\n'


def archive(path,infos,data,comment,final=False,changed=False):
    removed=[]
    with zipfile.ZipFile(path,'w',allowZip64=True) as z:
        z.comment=comment
        for info in infos:
            name=info.filename
            if final and changed and (re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)$',name,re.I) or name.upper()=='META-INF/INDEX.LIST'):
                removed.append(name); continue
            b=data[name]
            if final and changed and name.upper()=='META-INF/MANIFEST.MF': b=clean_manifest(b)
            out=copy.copy(info)
            if not final: out.compress_type=zipfile.ZIP_STORED
            z.writestr(out,b)
    return removed


def run(args):
    source=Path(args.input).resolve(); dest=Path(args.output).resolve()
    report_path=Path(args.report).resolve() if args.report else dest.parent/'deobf-report.json'
    if source==dest: raise ValueError('Input and output must be different')
    if report_path in (source,dest): raise ValueError('Report must not overwrite a JAR')
    report={'input':str(source),'output':str(dest),'constants':{},'stringPools':{},'decryptors':[],
            'decryptedStrings':[],'unresolved':[],'errors':[],'iterations':[],
            'limitations':['Closed-world string-pool mutation audit; external reflection/JNI writes are not modeled.',
            'Replacing decrypted Strings with LDC interns them; reference identity is not preserved.',
            'Verification uses CheckClassAdapter data-flow checks and BasicVerifier without class loading; it is not a full JVM linkage test.',
            'Java 8 floating-point folding uses IEEE binary32/binary64; NaN arithmetic is preserved.'],
            'validation':{},'status':'running'}
    if not source.is_file(): raise FileNotFoundError('Input JAR not found: '+str(source))
    log('[+] Loading '+str(source)); start=time.monotonic()
    original={}; classes={}
    with zipfile.ZipFile(source) as z:
        infos=z.infolist(); comment=z.comment
        if len({i.filename for i in infos})!=len(infos): raise ValueError('Duplicate ZIP entries are ambiguous; refusing rewrite')
        for info in infos:
            if info.file_size>256*1024*1024: raise ValueError('ZIP entry exceeds 256 MiB safety limit')
            original[info.filename]=z.read(info)
    current=original.copy()
    for name,b in current.items():
        if name.endswith('.class'):
            try: classes[name]=ClassFile(b,name)
            except Exception as e: report['errors'].append({'class':name,'stage':'parse','reason':str(e),'preservedOriginal':True})
    log('[+] %d classes loaded; %d parse failures'%(len(classes),len(report['errors'])))
    runtime=build(download=not args.offline)
    failed=set(); modified=set(); ledger=[]; found={}; pool_details={}; unresolved=[]
    work_root=Path(__file__).resolve().parent/'.work'; work_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='run-',dir=work_root) as temp:
        work=Path(temp); current_jar=work/'current.jar'
        def apply(plans,iteration):
            plans={n:e for n,e in plans.items() if n not in failed}
            if not plans: return 0
            archive(current_jar,infos,current,comment)
            changed_zip,status=invoke(runtime,'rewrite',current_jar,plans,work)
            count=0
            with zipfile.ZipFile(changed_zip) as z:
                for name,edits in plans.items():
                    kind,reason=status[name]
                    if kind=='OK':
                        try:
                            b=z.read(name); c=ClassFile(b,name)
                        except Exception as ex: kind,reason='ERROR','Python post-write parse: '+str(ex)
                    if kind=='ERROR':
                        current[name]=original[name]; classes[name]=ClassFile(original[name],name)
                        modified.discard(name); failed.add(name)
                        ledger[:]=[e for e in ledger if e['entry']!=name]
                        report['errors'].append({'class':name,'stage':'write/verify','reason':reason,'preservedOriginal':True})
                        log('[!] Original class preserved: '+ascii(name)+' ('+ascii(reason[:150])+')')
                        continue
                    current[name]=b; classes[name]=c; modified.add(name)
                    for e in edits: ledger.append({**e,'entry':name,'iteration':iteration})
                    count+=len(edits)
            return count
        log('[MetadataCleanup] Removing only syntactically invalid signatures/invisible annotation descriptors')
        metadata_count=apply(passes.metadata_cleanup(classes),0)
        log('[+] malformed metadata values removed: %d'%metadata_count)
        for iteration in range(1,args.max_iterations+1):
            log('\n[+] Iteration %d'%iteration)
            row={'iteration':iteration}
            log('[ConstantDeobf]')
            row['constants']=apply(passes.constants(classes),iteration)
            log('[+] constant expressions replaced: %d'%row['constants'])
            log('[StringPoolerDeobf]')
            pools,details=passes.discover_pools(classes)
            for d in details: pool_details[(d['owner'],d['field'],d['descriptor'])]=d
            row['pools']=len(pools)
            log('[+] pools discovered: %d; strings recovered: %d'%(len(pools),sum(len(v) for v in pools.values())))
            row['pooledStrings']=apply(passes.pool_uses(classes,pools),iteration)
            log('[+] usages replaced: %d'%row['pooledStrings'])
            # Discovery after pool rewriting exposes algorithm constants.
            for ref,d in passes.candidates(classes).items():
                if ref in found: d['confirmed']=found[ref]['confirmed']
                found[ref]=d
            log('[StringDecrypt]')
            plans,unresolved=passes.decrypt(classes,found,pools)
            row['decryptedStrings']=apply(plans,iteration)
            row['unresolved']=len(unresolved)
            log('[+] candidates: %d; decrypted: %d; unresolved: %d'%(len(found),row['decryptedStrings'],len(unresolved)))
            report['iterations'].append(row)
            if not row['constants'] and not row['pooledStrings'] and not row['decryptedStrings']:
                report['fixedPoint']=True; log('[+] Fixed point reached'); break
        else:
            report['fixedPoint']=False; log('[!] Iteration safety limit reached')
        # Cleanup is deliberately conservative: preserve pool/decryptor classes
        # and exception handlers; remove invalidated signing metadata on output.
        log('\n[+] Validating %d modified classes'%len(modified))
        archive(current_jar,infos,current,comment)
        _,status=invoke(runtime,'verify',current_jar,{n:[] for n in sorted(modified)},work)
        for name,(kind,reason) in status.items():
            if kind=='ERROR':
                current[name]=original[name]; modified.remove(name)
                ledger[:]=[e for e in ledger if e['entry']!=name]
                report['errors'].append({'class':name,'stage':'final-verify','reason':reason,'preservedOriginal':True})
        counts=Counter()
        for e in ledger:
            if e['passName']=='ConstantDeobf': counts.update(e['counts'])
        report['constants']={dict(I='int',J='long',F='float',D='double')[k]:counts[k] for k in 'IJFD'}
        report['metadataCleanup']=[{'class':e['entry'],'kind':e['desc']} for e in ledger if e['passName']=='MetadataCleanup']
        report['stringPools']={'pools':list(pool_details.values()),'usagesReplaced':sum(e['passName']=='StringPoolerDeobf' for e in ledger)}
        report['decryptedStrings']=[{**e['decrypted'],'iteration':e['iteration'],'offsetBasis':'class bytecode at start of this iteration StringDecrypt pass'} for e in ledger if e['passName']=='StringDecrypt']
        confirmed={(e['decryptor']['owner'],e['decryptor']['method'],e['decryptor']['descriptor']) for e in report['decryptedStrings']}
        for ref,d in found.items(): d['confirmed']=ref in confirmed
        report['decryptors']=list(found.values()); report['unresolved']=unresolved
        report['validation']={'modifiedClasses':sorted(modified),'verifiedCount':len(modified),
            'checks':['Python class parser','ASM CheckClassAdapter(checkDataFlow=true)','ASM Analyzer(BasicVerifier)'],
            'frames':'Original frames preserved and relocated; COMPUTE_MAXS. Replacements cannot cross frame/branch/handler boundaries.',
            'targetClassesLoaded':False}
        dest.parent.mkdir(parents=True,exist_ok=True)
        report_path.parent.mkdir(parents=True,exist_ok=True)
        log('[+] Writing '+str(dest))
        fd,tmp=tempfile.mkstemp(prefix=dest.name+'.',suffix='.tmp',dir=dest.parent); os.close(fd)
        tmp=Path(tmp)
        try:
            report['removedSigningMetadata']=archive(tmp,infos,current,comment,final=True,changed=bool(modified))
            with zipfile.ZipFile(tmp) as z:
                bad=z.testzip()
                if bad: raise ValueError('Output ZIP CRC failure: '+bad)
                for name in modified:
                    b=z.read(name); ClassFile(b,name)
                    if b!=current[name]: raise ValueError('Output class mismatch')
                preserved_resources=0
                for name,b in original.items():
                    if name.endswith('.class') or name in report['removedSigningMetadata'] or name.upper()=='META-INF/MANIFEST.MF': continue
                    if z.read(name)!=b: raise ValueError('Resource changed: '+name)
                    preserved_resources+=1
            report['validation']['outputReopened']=True
            report['validation']['resourcesByteIdentical']=preserved_resources
            report['validation']['inputSHA256']=hashlib.sha256(source.read_bytes()).hexdigest()
            report['validation']['outputSHA256']=hashlib.sha256(tmp.read_bytes()).hexdigest()
            os.replace(tmp,dest)
        finally:
            if tmp.exists(): tmp.unlink()
    report['elapsedSeconds']=round(time.monotonic()-start,2)
    report['status']='completed_with_unresolved' if report['unresolved'] or report['errors'] or not report.get('fixedPoint') else 'completed'
    report_path.write_text(json.dumps(report,ensure_ascii=True,indent=2),encoding='utf-8')
    log('[+] Done. Modified classes: %d; decrypted strings: %d; errors: %d'%(len(modified),len(report['decryptedStrings']),len(report['errors'])))
    log('[+] Report: '+str(report_path))
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input',nargs='?',default=str(DEFAULT_DIR/'AntiHack.jar'))
    p.add_argument('output',nargs='?',default=str(DEFAULT_DIR/'AntiHack-deobf.jar'))
    p.add_argument('--report',help='Default: deobf-report.json beside output JAR')
    p.add_argument('--max-iterations',type=int,default=12)
    p.add_argument('--offline',action='store_true',help='Require already downloaded ASM dependencies')
    args=p.parse_args()
    if not 1<=args.max_iterations<=100: p.error('--max-iterations must be in 1..100')
    try: run(args)
    except Exception as e:
        log('[!] Failed: '+type(e).__name__+': '+str(e))
        return 1
    return 0


if __name__=='__main__': sys.exit(main())
