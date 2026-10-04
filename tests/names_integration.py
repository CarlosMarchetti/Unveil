"""Execute only authored fixtures to validate NameRecovery end to end."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deobf.names.analysis import Index, suggest
from deobf.names.mappings import empty, record, write, sha256
from deobf.names.safety import validate
from deobf.names.remap import apply
from deobf.writer import build


def check(condition, message):
    if not condition: raise AssertionError(message)


def main():
    runtime = build(False); java, cp = runtime
    work = ROOT/'test-output/name-fixtures'; work.mkdir(parents=True, exist_ok=True)
    classes = work/'classes'; classes.mkdir(exist_ok=True)
    sources = {
        'I': 'package p; public interface I { int a(int x); }',
        'A': 'package p; public class A implements I { public int q=7; public int a(int x){return x*3+q;} public static int b(){return 29;} }',
        'B': 'package p; public class B extends A { public int a(int x){return super.a(x)+11;} }',
        'R': 'package p; public class R implements Runnable {public void run(){} public Class<?> lookup(String n)throws Exception{return Class.forName(n);} }',
        'S': 'package p; public class S implements java.io.Serializable {private static final long serialVersionUID=1;}',
        'T': 'package p; public class T {}',
        'D': 'package p; public class D extends T {public int a(){return 17;}}',
        'E': 'package p; public class E extends T {public int a(){return 19;}}',
        'C': '''package p; public class C {
            public static int a(int x){return (x*13+101)^43;}
            public static int b(int x){return (x*17+103)^47;}
            public static int c(int x){return (x*19+107)^53;}
            public static int d(int x){return (x*23+109)^59;}
            private static String z(String x){return x.trim();}
        }''',
        'Main': '''package p; import java.util.*; import java.util.function.*;
            public class Main {public static void main(String[] args){
                B b=new B(); System.out.println(b.a(2));System.out.println(b.q);System.out.println(B.b());
                IntUnaryOperator f=b::a;System.out.println(f.applyAsInt(4));
                for(I service:ServiceLoader.load(I.class))System.out.println(service.a(5));
            }}''',
    }
    paths = []
    for name, source in sources.items():
        path=work/(name+'.java'); path.write_text(source, encoding='utf-8'); paths.append(str(path))
    javac=shutil.which('javac')
    subprocess.run([javac,'-encoding','UTF-8','-source','8','-target','8','-d',str(classes),*paths],check=True)
    source=work/'source.jar'; output=work/'named.jar'
    with zipfile.ZipFile(source,'w') as z:
        for path in classes.rglob('*.class'): z.write(path,path.relative_to(classes).as_posix())
        z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\nMain-Class: p.Main\r\n\r\n')
        z.writestr('META-INF/services/p.I','p.B # implementation\n')
        z.writestr('assets/data.json','{"unchanged":42}')
    baseline=subprocess.check_output([java,'-Xverify:all','-jar',str(source)])
    mappings=empty()
    for a,b in [('p/A','p/Base'),('p/B','p/Implementation'),('p/I','p/Operation'),('p/Main','p/Launcher')]:
        mappings['classes'].append(record('classes',None,a,None,b))
    mappings['methods']=[record('methods','p/I','a','(I)I','compute'),record('methods','p/A','b','()I','constant')]
    mappings['fields']=[record('fields','p/A','q','I','count')]
    index=Index(source)
    approved,issues,aliases=validate(index,mappings)
    check(not issues,repr(issues))
    check(len(approved['methods'])==4,'Override family must include interface, base, child and static method')
    result=apply(index,output,approved,aliases,True)
    check(result['outputReopened'],'Archive must be reopened')
    check(subprocess.check_output([java,'-Xverify:all','-jar',str(output)])==baseline,'Behavior changed')
    with zipfile.ZipFile(output) as z:
        check('p/Base.class' in z.namelist() and 'p/A.class' not in z.namelist(),'Class entries not renamed')
        check(z.read('META-INF/services/p.Operation')==b'p.Implementation # implementation\n','Service metadata not remapped')
        check(z.read('assets/data.json')==b'{"unchanged":42}','Unrelated resource changed')
    # Named output is also a reference for recovering the original obfuscated names.
    ref=Index(output)
    guesses,evidence=suggest(index,ref)
    check(any(x['from']=='p/B' and x['to']=='p/Implementation' for x in guesses['classes']), 'Reference class recovery failed')
    check(any(x['from']=='a' and x['to']=='compute' for x in guesses['methods']), 'Reference method recovery failed')
    check(any(x['from']=='q' and x['to']=='count' for x in guesses['fields']), 'Reference field recovery failed')
    # A whole-class fingerprint differs because only the target has an injected
    # helper. Independent matching bodies should still recover approved names.
    reference_source = work/'Arithmetic.java'
    reference_source.write_text(sources['C'].replace('class C', 'class Arithmetic')
        .replace('int a(', 'int first(').replace('int b(', 'int second(')
        .replace('int c(', 'int third(').replace('int d(', 'int fourth(')
        .replace('private static String z(String x){return x.trim();}', ''), encoding='utf-8')
    reference_classes = work/'reference-classes'; reference_classes.mkdir(exist_ok=True)
    subprocess.run([javac,'-source','8','-target','8','-d',str(reference_classes),str(reference_source)],check=True)
    partial_reference = work/'partial-reference.jar'
    with zipfile.ZipFile(partial_reference, 'w') as z:
        z.write(reference_classes/'p/Arithmetic.class', 'p/Arithmetic.class')
    partial, _ = suggest(index, Index(partial_reference))
    check(any(x['from']=='p/C' and x['to']=='p/Arithmetic' and x['approved'] for x in partial['classes']),
          'Injected helper incorrectly prevents high-confidence class matching')
    check(len([x for x in partial['methods'] if x['owner']=='p/C' and x['approved']]) == 4,
          'Partial class matching did not recover its four independent methods')
    mapping_file=work/'reviewed.json'; write(mapping_file,{**mappings,'sourceSHA256':sha256(source)})
    subprocess.run([sys.executable,str(ROOT/'main.py'),str(source),str(work/'cli.jar'),'--apply-mappings',str(mapping_file),'--names-dir',str(work/'reports'),'--offline'],check=True)
    check(subprocess.check_output([java,'-Xverify:all','-jar',str(work/'cli.jar')])==baseline,'CLI remap behavior changed')
    subprocess.run([sys.executable,str(ROOT/'main.py'),str(source),'--recover-names','--reference',str(output),'--names-dir',str(work/'analysis'),'--offline'],check=True)
    check((work/'analysis/mappings.json').is_file(),'Missing review artifact')
    # Native/reflection/serialization names, collisions and package splitting.
    bad=empty(); bad['classes']=[record('classes',None,'p/R',None,'p/Reflect'),record('classes',None,'p/S',None,'p/Serial')]
    check(len(validate(index,bad)[1])==2,'Indirect-name constraints not enforced')
    bad=empty();bad['classes']=[record('classes',None,'p/A',None,'p/B')]
    check(bool(validate(index,bad)[1]),'Class collision not rejected')
    bad=empty();bad['classes']=[record('classes',None,'p/A',None,'other/Base')]
    check(bool(validate(index,bad)[1]),'Unsafe partial package move not rejected')
    bad=empty();bad['methods']=[record('methods','p/I','a','(I)I','one'),record('methods','p/B','a','(I)I','two')]
    selected,issues,_=validate(index,bad)
    check(not selected['methods'] and issues,'Conflicting override family not rejected')
    siblings=empty(); siblings['methods']=[record('methods','p/D','a','()I','left'),record('methods','p/E','a','()I','right')]
    selected,issues,_=validate(index,siblings)
    check(not issues and len(selected['methods'])==2,'Unrelated sibling declarations incorrectly grouped as overrides')
    # The bytecode verifier must also reject an invalid low-level plan atomically.
    before=output.read_bytes()
    impossible=empty();impossible['classes']=[record('classes',None,'p/A',None,'invalid;Name')]
    try: apply(index,output,impossible,{'methods':{},'fields':{}},True)
    except ValueError: pass
    else: raise AssertionError('Invalid remap unexpectedly succeeded')
    check(output.read_bytes()==before,'Failed transaction overwrote existing output')
    wrong=work/'wrong.json';write(wrong,{**mappings,'sourceSHA256':'0'*64})
    p=subprocess.run([sys.executable,str(ROOT/'main.py'),str(source),str(output),'--apply-mappings',str(wrong),'--names-dir',str(work/'wrong-report'),'--offline'],capture_output=True)
    check(p.returncode!=0 and output.read_bytes()==before,'Mismatched SHA was accepted')
    print('NameRecovery integration passed: matching, members, inheritance, lambdas, services, manifest, collisions, review and atomic rollback.')


if __name__=='__main__': main()
