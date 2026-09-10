import math
import struct
import unittest
from deobf.values import Value as V, arithmetic, Unresolved
from deobf.classfile import ClassFile, Insn, Method, mutf8
from deobf.passes import constants, candidates
from deobf.crypto import call, Object, byte_array
from deobf.interpreter import Interpreter


class CoreTests(unittest.TestCase):
    def test_int_long_arithmetic(self):
        self.assertEqual(arithmetic(126,[V('I',0x2dc7),V('I',0xcf)]).value,199)
        self.assertEqual(arithmetic(126,[V('I',-24358491),V('I',973)]).value,-24358491 & 973)
        for k,bits,offset in [('I',32,0),('J',64,1)]:
            low=-(1<<(bits-1)); high=(1<<(bits-1))-1
            self.assertEqual(arithmetic(96+offset,[V(k,high),V(k,1)]).value,low)
            self.assertEqual(arithmetic(108+offset,[V(k,low),V(k,-1)]).value,low)
            self.assertEqual(arithmetic(108+offset,[V(k,-7),V(k,3)]).value,-2)
            self.assertEqual(arithmetic(124+offset,[V(k,-1),V('I',-1)]).value,1)
            self.assertEqual(arithmetic(120+offset,[V(k,1),V('I',bits)]).value,1)
            self.assertEqual(arithmetic(116+offset,[V(k,low)]).value,low)
            with self.assertRaises(Unresolved): arithmetic(108+offset,[V(k,1),V(k,0)])

    def test_float_semantics(self):
        self.assertEqual(arithmetic(98,[V('F',16777216.),V('F',1.)]).value,16777216.)
        self.assertEqual(arithmetic(99,[V('D',16777216.),V('D',1.)]).value,16777217.)
        self.assertEqual(arithmetic(110,[V('F',1.),V('F',0.)]).value,math.inf)
        self.assertEqual(math.copysign(1,arithmetic(106,[V('F',-0.),V('F',2.)]).value),-1)
        with self.assertRaises(Unresolved): arithmetic(111,[V('D',0.),V('D',0.)])

    def test_modified_utf8(self):
        self.assertEqual(mutf8(b'a\xc0\x80b'),'a\0b')
        self.assertEqual(mutf8(bytes.fromhex('eda0bdedb880')),'\U0001f600')
        self.assertEqual(mutf8(bytes.fromhex('eda080')),'\ud800')

    def test_deny_api(self):
        for owner,name,desc in [('java/lang/Runtime','exec','(Ljava/lang/String;)Ljava/lang/Process;'),('java/lang/Class','forName','(Ljava/lang/String;)Ljava/lang/Class;')]:
            with self.assertRaises(Unresolved): call(owner,name,desc,None,[V('S','x')],[])

    def test_boundary_blocks_folding(self):
        m=Method(8,'x','()I',[Insn(4,None,0,0,1),Insn(5,None,1,1,2,True),Insn(96,None,2,2,3)])
        class C: methods=[m]
        self.assertFalse(constants({'x':C()}))

    def test_base64_alone_not_candidate(self):
        m=Method(8,'x','(Ljava/lang/String;)Ljava/lang/String;',[Insn(182,('java/util/Base64$Decoder','decode','([B)[B'),0,0,1)])
        class C: name='X'; methods=[m]
        self.assertFalse(candidates({'x':C()}))

    def test_interpreter_loop_budget(self):
        m=Method(8,'x','()V',[Insn(167,0,0,0,1)])
        class C: name='X'; methods=[m]
        with self.assertRaisesRegex(Unresolved,'budget'):
            Interpreter({'X':C()},steps=10).run('X',m)

    def test_interpreter_blocks_processbuilder(self):
        m=Method(8,'x','()V',[Insn(187,'java/lang/ProcessBuilder',0,0,1)])
        class C: name='X'; methods=[m]
        with self.assertRaisesRegex(Unresolved,'not allowlisted'):
            Interpreter({'X':C()}).run('X',m)

    def test_base64_padding_matches_jdk_constraints(self):
        decoder=call('java/util/Base64','getDecoder','()Ljava/util/Base64$Decoder;',None,[],[])
        with self.assertRaises(Unresolved):
            call('java/util/Base64$Decoder','decode','(Ljava/lang/String;)[B',decoder,[V('S','AA=')],[])
        good=call('java/util/Base64$Decoder','decode','(Ljava/lang/String;)[B',decoder,[V('S','AA')],[])
        self.assertEqual(good.value.data['value'],b'\0')

    def test_all_requested_binary_operations(self):
        expected={96:10,100:4,104:21,108:2,120:56,122:0,124:0,126:3,128:7,130:4}
        for op,result in expected.items():
            self.assertEqual(arithmetic(op,[V('I',7),V('I',3)]).value,result)
            self.assertEqual(arithmetic(op+1,[V('J',7),V('I' if op in (120,122,124) else 'J',3)]).value,result)
        for op,result in {98:10.,102:4.,106:21.,110:7./3.}.items():
            self.assertAlmostEqual(arithmetic(op,[V('F',7.),V('F',3.)]).value,result,places=6)
            self.assertEqual(arithmetic(op+1,[V('D',7.),V('D',3.)]).value,result)


if __name__=='__main__': unittest.main()
