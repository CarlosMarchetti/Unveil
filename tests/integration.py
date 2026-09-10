"""End-to-end tests execute ONLY authored fixtures, never AntiHack.jar."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
from Crypto.Cipher import AES,DES,Blowfish
from Crypto.Util.Padding import pad

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from deobf.writer import build,invoke
from deobf.classfile import ClassFile


def main():
    runtime=build(False); java,cp=runtime
    work=ROOT/'test-output/fixtures'; work.mkdir(parents=True,exist_ok=True)
    classes=work/'classes'; classes.mkdir(exist_ok=True)
    javac=shutil.which('javac')
    subprocess.run([javac,'-encoding','UTF-8','-source','8','-target','8','-cp',cp,'-d',str(classes),str(ROOT/'tests/Generate.java')],check=True)
    subprocess.run([java,'-cp',str(classes)+os.pathsep+cp,'Generate',str(classes)],check=True)
    methods=[]; uses=[]
    for n,(module,alg,mode,key_len) in enumerate([(AES,'AES','ECB',16),(DES,'DES','ECB',8),(Blowfish,'Blowfish','ECB',16),(AES,'AES','CBC',16)]):
        key=hashlib.md5(b'test-key').digest()[:key_len]
        iv=bytes(range(16)); kwargs={'iv':iv} if mode=='CBC' else {}
        encrypted=base64.b64encode(module.new(key,module.MODE_CBC if mode=='CBC' else module.MODE_ECB,**kwargs).encrypt(pad(('plain-'+str(n)).encode(),module.block_size))).decode()
        init='cipher.init(2,key,new IvParameterSpec(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}));' if mode=='CBC' else 'cipher.init(2,key);'
        methods.append('''private static String x%s(String a,String b) { try {
          SecretKeySpec key=new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("MD5").digest(b.getBytes(StandardCharsets.UTF_8)),%s),"%s");
          Cipher cipher=Cipher.getInstance("%s/%s/PKCS5Padding"); %s
          return new String(cipher.doFinal(Base64.getDecoder().decode(a.getBytes(StandardCharsets.UTF_8))),StandardCharsets.UTF_8);
        } catch(Exception e) { e.printStackTrace(); return null; } }'''%(n,key_len,alg,alg,mode,init))
        uses.append('System.out.println(x%s("%s",local));'%(n,encrypted))
    xor_key='abc'; plain='xor-result'
    ciphertext=base64.b64encode(''.join(chr(ord(c)^ord(xor_key[i%3])) for i,c in enumerate(plain)).encode()).decode()
    methods.append('''private static String strange(String a,String b) {
      a=new String(Base64.getDecoder().decode(a.getBytes(StandardCharsets.UTF_8)),StandardCharsets.UTF_8);
      StringBuilder r=new StringBuilder(); char[] key=b.toCharArray(); int i=0;
      for(char c:a.toCharArray()) {r.append((char)(c^key[i%key.length])); i++;} return r.toString(); }''')
    uses.append('System.out.println(strange("%s","abc"));'%ciphertext)
    reverse_cipher=base64.b64encode(DES.new(hashlib.md5(b'test-key').digest()[:8],DES.MODE_ECB).encrypt(pad(b'reversed-args',8))).decode()
    methods.append('''private static String reversed(String keyText,String ciphertext) { try {
      SecretKeySpec key=new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("MD5").digest(keyText.getBytes(StandardCharsets.UTF_8)),8),"DES");
      Cipher cipher=Cipher.getInstance("DES"); cipher.init(2,key);
      return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)),StandardCharsets.UTF_8);
    } catch(Exception e) {return null;} }''')
    uses.append('System.out.println(reversed("test-key","%s"));'%reverse_cipher)
    source='''import java.util.*; import java.nio.charset.*; import java.security.*; import javax.crypto.*; import javax.crypto.spec.*;
    public class Fixture { %s
      public static void main(String[] args) {
        String local="test-".concat("key"); %s
        System.out.println(p.Renamed.data[0].length());
        System.out.println((int)p.Renamed.data[1].charAt(0));
        System.out.println(Numeric.number()); System.out.println(Numeric.overflow());
        System.out.println(Float.floatToRawIntBits(Numeric.negativeZero()));
        System.out.println(Numeric.branch(true));System.out.println(Numeric.branch(false));System.out.println(Numeric.division());
      }
    }'''%('\n'.join(methods),'\n'.join(uses))
    source_path=work/'Fixture.java'; source_path.write_text(source,encoding='utf-8')
    subprocess.run([javac,'-encoding','UTF-8','-source','8','-target','8','-cp',str(classes),'-d',str(classes),str(source_path)],check=True)
    original=work/'fixture.jar'; output=work/'fixture-deobf.jar'
    with zipfile.ZipFile(original,'w') as z:
        for p in classes.rglob('*.class'):
            if p.name!='Generate.class': z.write(p,p.relative_to(classes).as_posix())
        z.writestr('assets/test.json','{"preserved":true}')
        z.writestr('META-INF/TEST.SF','invalidated signing data')
        z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\r\nMain-Class: Fixture\r\n\r\nName: Fixture.class\r\nSHA-256-Digest: obsolete\r\n\r\n')
    baseline=subprocess.check_output([java,'-Xverify:all','-cp',str(original),'Fixture'])
    subprocess.run([sys.executable,str(ROOT/'main.py'),str(original),str(output),'--offline'],check=True)
    result=subprocess.check_output([java,'-Xverify:all','-cp',str(output),'Fixture'])
    assert baseline==result,(baseline,result)
    report=json.loads((work/'deobf-report.json').read_text())
    assert len(report['decryptedStrings'])==6,report['unresolved']
    assert report['stringPools']['usagesReplaced']==2,report['stringPools']
    assert not report['errors'],report['errors']
    assert 'test-key' not in json.dumps(report['decryptedStrings'])
    assert next(e for e in report['decryptedStrings'] if e['plaintext']=='reversed-args')['ciphertext']==reverse_cipher
    with zipfile.ZipFile(output) as z:
        assert 'META-INF/TEST.SF' not in z.namelist()
        assert z.read('assets/test.json')==b'{"preserved":true}'
        assert b'Main-Class: Fixture' in z.read('META-INF/MANIFEST.MF')
        assert b'Digest' not in z.read('META-INF/MANIFEST.MF')
        c=ClassFile(z.read('Numeric.class'))
        assert any(i.op==108 for m in c.methods for i in m.insns),'Division by zero must remain'
    # Deliberately invalid plan must be rejected and publish no changed class.
    bad={'Numeric.class':[{'method':'number','desc':'()I','start':0,'end':3,'replacement':[('S','wrong type')]}]}
    changes,status=invoke(runtime,'rewrite',original,bad,work)
    assert status['Numeric.class'][0]=='ERROR',status
    with zipfile.ZipFile(changes) as z: assert not z.namelist()
    j8=Path(r'R:\Sunshine\Sunshine\data\java\jre1.8.0_451\bin\java.exe')
    if j8.exists():
        assert subprocess.check_output([str(j8),'-Xverify:all','-cp',str(output),'Fixture'])==baseline
        print('Java 8 -Xverify:all fixture validation passed')
    print('Integration passed: 6 decryptions; reversed argument privacy; renamed pool; arithmetic; frames; resources; invalid-class rejection.')


if __name__=='__main__': main()
