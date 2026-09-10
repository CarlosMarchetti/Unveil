"""Explicit deterministic models of JDK APIs; all cryptography runs in Python."""
import base64
import hashlib
import re
from dataclasses import dataclass, field
from Crypto.Cipher import AES, DES, DES3, Blowfish
from Crypto.Util.Padding import unpad
from .values import Value as V, Unresolved

LIMIT=1_000_000


@dataclass
class Object:
    type: str
    data: dict = field(default_factory=dict)


def raw(v):
    if v.kind=='A': return bytes(x.value & 255 for x in v.value)
    if v.kind=='O' and v.value.type=='bytes': return v.value.data['value']
    raise Unresolved('Expected byte array')


def byte_array(b):
    if len(b)>LIMIT: raise Unresolved('Array size budget exceeded')
    return V('O',Object('bytes',{'value':bytes(b)}))


def string(v):
    if v.kind=='S': return v.value
    if v.kind=='O' and v.value.type=='java/lang/String' and 'value' in v.value.data: return v.value.data['value']
    raise Unresolved('Expected known String')


def encoding(v):
    name=string(v) if v.kind=='S' else v.value.data.get('name') if v.kind=='O' and v.value.type=='charset' else None
    names={'UTF-8':'utf-8','UTF-16':'utf-16','UTF-16BE':'utf-16-be','UTF-16LE':'utf-16-le','US-ASCII':'ascii','ISO-8859-1':'latin-1'}
    if name not in names: raise Unresolved('Unsupported charset')
    return names[name]


def obj(v,t):
    if v is None or v.kind!='O' or v.value.type!=t: raise Unresolved('Unexpected API receiver')
    return v.value.data


def call(owner,name,desc,receiver,args,events):
    # Match descriptors as well as names; unlisted overloads fail closed.
    sig=(name,desc)
    if owner=='java/lang/String':
        if sig==('<init>','([BLjava/nio/charset/Charset;)V') or sig==('<init>','([BLjava/lang/String;)V'):
            b=raw(args[0]); codec=encoding(args[1])
            # Invalid input is left unresolved: Python and Java replacement-byte
            # grouping differs for malformed UTF-8/UTF-16.
            obj(receiver,owner)['value']=b.decode(codec,'strict'); return None
        if sig==('<init>','(Ljava/lang/String;)V'):
            obj(receiver,owner)['value']=string(args[0]); return None
        if sig in (('getBytes','(Ljava/nio/charset/Charset;)[B'),('getBytes','(Ljava/lang/String;)[B')):
            return byte_array(string(receiver).encode(encoding(args[0]),'strict'))
        if sig==('concat','(Ljava/lang/String;)Ljava/lang/String;'):
            s=string(receiver)+string(args[0])
            if len(s)>LIMIT: raise Unresolved('String budget exceeded')
            return V('S',s)
        if sig==('length','()I'): return V('I',len(string(receiver).encode('utf-16-be','surrogatepass'))//2)
        if sig==('toCharArray','()[C'):
            b=string(receiver).encode('utf-16-be','surrogatepass')
            return V('A',[V('I',int.from_bytes(b[p:p+2],'big')) for p in range(0,len(b),2)])
        if sig==('valueOf','(Ljava/lang/Object;)Ljava/lang/String;'):
            a=args[0]
            if a.kind=='N': return V('S','null')
            if a.kind=='O' and a.value.type=='java/lang/StringBuilder': return V('S',a.value.data['value'])
            return V('S',string(a))
        if sig==('intern','()Ljava/lang/String;'): return V('S',string(receiver))
        if sig==('toString','()Ljava/lang/String;'): return V('S',string(receiver))
        if sig==('equals','(Ljava/lang/Object;)Z'): return V('I',int(string(receiver)==string(args[0])))
        if sig==('substring','(I)Ljava/lang/String;') or sig==('substring','(II)Ljava/lang/String;'):
            b=string(receiver).encode('utf-16-be','surrogatepass'); a=args[0].value; z=args[1].value if len(args)>1 else len(b)//2
            if not 0<=a<=z<=len(b)//2: raise Unresolved('String index out of bounds')
            return V('S',b[2*a:2*z].decode('utf-16-be','surrogatepass'))
        if sig==('charAt','(I)C'):
            b=string(receiver).encode('utf-16-be','surrogatepass'); i=args[0].value
            if not 0<=i<len(b)//2: raise Unresolved('String index out of bounds')
            return V('I',int.from_bytes(b[2*i:2*i+2],'big'))
    if owner=='java/lang/StringBuilder':
        d=obj(receiver,owner)
        if sig==('<init>','()V'): d['value']=''; return None
        if sig==('<init>','(Ljava/lang/String;)V'): d['value']=string(args[0]); return None
        if sig==('toString','()Ljava/lang/String;'): return V('S',d['value'])
        if sig==('append','(C)Ljava/lang/StringBuilder;') or sig==('append','(Ljava/lang/String;)Ljava/lang/StringBuilder;'):
            d['value']+=chr(args[0].value&65535) if desc.startswith('(C)') else string(args[0])
            if len(d['value'])>LIMIT: raise Unresolved('String budget exceeded')
            return receiver
    if owner=='java/util/Base64' and desc=='()Ljava/util/Base64$Decoder;' and name in ('getDecoder','getUrlDecoder','getMimeDecoder'):
        return V('O',Object('decoder',{'variant':name}))
    if owner=='java/util/Base64$Decoder' and name=='decode' and desc in ('([B)[B','(Ljava/lang/String;)[B'):
        variant=obj(receiver,'decoder')['variant']; b=raw(args[0]) if desc=='([B)[B' else string(args[0]).encode('latin-1','strict')
        original_input=b.decode('latin-1')
        if variant=='getMimeDecoder': b=re.sub(rb'[^A-Za-z0-9+/=]',b'',b)
        if variant=='getUrlDecoder':
            if b'+' in b or b'/' in b: raise Unresolved('Invalid URL Base64 alphabet')
            b=b.replace(b'-',b'+').replace(b'_',b'/')
        if b'=' in b:
            padding=len(b)-len(b.rstrip(b'='))
            if len(b)%4 or padding not in (1,2) or b'=' in b[:-padding]: raise Unresolved('Invalid Base64 padding')
        elif len(b)%4==1: raise Unresolved('Invalid Base64 length')
        else: b+=b'='*((-len(b))%4)
        decoded=byte_array(base64.b64decode(b,validate=True))
        decoded.value.data['base64Source']=original_input
        events.append({'base64Input':original_input})
        return decoded
    if owner=='java/security/MessageDigest':
        if sig==('getInstance','(Ljava/lang/String;)Ljava/security/MessageDigest;'):
            name=string(args[0]); alg={'MD5':'md5','SHA':'sha1','SHA-1':'sha1','SHA-224':'sha224','SHA-256':'sha256','SHA-384':'sha384','SHA-512':'sha512','MD2':'md2'}.get(name.upper())
            if not alg: raise Unresolved('Unsupported digest algorithm')
            return V('O',Object('digest',{'algorithm':alg,'input':b''}))
        if sig==('update','([B)V'):
            d=obj(receiver,'digest'); d['input']+=raw(args[0])
            if len(d['input'])>LIMIT: raise Unresolved('Digest size budget exceeded')
            return None
        if sig in (('digest','([B)[B'),('digest','()[B')):
            d=obj(receiver,'digest'); b=d['input']+(raw(args[0]) if args else b''); d['input']=b''
            if d['algorithm']=='md2':
                from Crypto.Hash import MD2
                digest=MD2.new(b).digest()
            else: digest=hashlib.new(d['algorithm'],b).digest()
            return byte_array(digest)
    if owner=='java/util/Arrays':
        if sig==('copyOf','([BI)[B'):
            b=raw(args[0]); n=args[1].value
            if not 0<=n<=LIMIT: raise Unresolved('Array size budget exceeded')
            return byte_array(b[:n]+bytes(max(0,n-len(b))))
        if sig==('copyOfRange','([BII)[B'):
            b=raw(args[0]); a,z=args[1].value,args[2].value
            if not 0<=a<=len(b) or not a<=z<=LIMIT: raise Unresolved('Array range invalid')
            return byte_array(b[a:z]+bytes(max(0,z-len(b))))
    if owner=='javax/crypto/spec/SecretKeySpec' and name=='<init>':
        if desc=='([BLjava/lang/String;)V': b=raw(args[0]); algorithm=string(args[1])
        elif desc=='([BIILjava/lang/String;)V':
            b=raw(args[0]); a,n=args[1].value,args[2].value
            if a<0 or n<=0 or a+n>len(b): raise Unresolved('Key slice invalid')
            b=b[a:a+n]; algorithm=string(args[3])
        else: raise Unresolved('Unsupported key constructor')
        if not b: raise Unresolved('Empty key')
        obj(receiver,owner).update(key=b,algorithm=algorithm); return None
    if owner=='javax/crypto/spec/IvParameterSpec' and sig==('<init>','([B)V'):
        obj(receiver,owner)['iv']=raw(args[0]); return None
    if owner=='javax/crypto/Cipher':
        if sig==('getInstance','(Ljava/lang/String;)Ljavax/crypto/Cipher;'):
            return V('O',Object('cipher',{'transformation':string(args[0])}))
        if name=='init' and desc in ('(ILjava/security/Key;)V','(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V'):
            d=obj(receiver,'cipher'); key=obj(args[1],'javax/crypto/spec/SecretKeySpec')
            if args[0].kind!='I' or args[0].value!=2: raise Unresolved('Only DECRYPT_MODE is modeled')
            d.update(key=key['key'],key_algorithm=key['algorithm'])
            if len(args)==3: d['iv']=obj(args[2],'javax/crypto/spec/IvParameterSpec')['iv']
            return None
        if sig==('doFinal','([B)[B'):
            d=obj(receiver,'cipher'); parts=d['transformation'].split('/')
            if len(parts)==1: parts += ['ECB','PKCS5Padding']
            if len(parts)!=3: raise Unresolved('Unsupported cipher transformation')
            algorithm,mode,padding=parts
            algorithms={'AES':AES,'DES':DES,'DESEDE':DES3,'BLOWFISH':Blowfish}
            module=algorithms.get(algorithm.upper())
            if not module: raise Unresolved('Unsupported cipher algorithm: '+algorithm)
            if d.get('key_algorithm','').upper()!=algorithm.upper(): raise Unresolved('Key/cipher algorithm mismatch')
            key=d.get('key'); kwargs={}
            if mode.upper()=='ECB': cipher_mode=module.MODE_ECB
            elif mode.upper()=='CBC':
                cipher_mode=module.MODE_CBC
                if 'iv' not in d: raise Unresolved('CBC requires explicit IV')
                kwargs['iv']=d['iv']
            else: raise Unresolved('Unsupported cipher mode: '+mode)
            if padding.upper() not in ('PKCS5PADDING','NOPADDING'): raise Unresolved('Unsupported cipher padding')
            plaintext=module.new(key,cipher_mode,**kwargs).decrypt(raw(args[0]))
            if padding.upper()=='PKCS5PADDING': plaintext=unpad(plaintext,module.block_size)
            origin=args[0].value.data.get('base64Source') if args[0].kind=='O' else None
            events.append({'transformation':d['transformation'],'algorithm':algorithm,'mode':mode,'padding':padding,'ciphertextInput':origin})
            return byte_array(plaintext)
    raise Unresolved('API not allowlisted: '+owner+'.'+name+desc)
