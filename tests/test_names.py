import tempfile
from pathlib import Path
import unittest
from deobf.names.mappings import read, write, write_tiny, empty
from deobf.names.analysis import partial_confirmation


class MappingTests(unittest.TestCase):
    def test_partial_match_with_injected_helpers(self):
        self.assertTrue(partial_confirmation({'ref': 6}, {'target': 6}, 8, False))
        self.assertTrue(partial_confirmation({'ref': 3}, {'target': 3}, 10, True))

    def test_partial_match_rejects_weak_and_competing_evidence(self):
        self.assertFalse(partial_confirmation({'ref': 2}, {'target': 2}, 2, True))
        self.assertFalse(partial_confirmation({'ref': 6}, {'target': 6, 'clone': 6}, 8, True))
        self.assertFalse(partial_confirmation({'ref': 6, 'other': 3}, {'target': 6}, 8, True))
        self.assertFalse(partial_confirmation({'ref': 3}, {'target': 3}, 30, True))
    def parse(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'map.txt'; p.write_text(text, encoding='utf-8')
            return read(p)

    def test_tiny_v2_roundtrip(self):
        data = self.parse('tiny\t2\t0\tobf\tnamed\nc\tp/A\tp/Screen\n\tf\tI\ta\tcount\n\tm\t(I)I\tb\tcompute\n')
        self.assertEqual(data['methods'][0]['owner'], 'p/A')
        self.assertEqual(data['fields'][0]['to'], 'count')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'out.tiny'; write_tiny(p, data)
            self.assertEqual(read(p), data)

    def test_tiny_v1(self):
        data = self.parse('v1\tobf\tnamed\nCLASS\tp/A\tp/Screen\nMETHOD\tp/A\t()V\ta\tstart\nFIELD\tp/A\tI\tb\tcount\n')
        self.assertEqual(data['methods'][0]['descriptor'], '()V')
        self.assertEqual(data['fields'][0]['from'], 'b')

    def test_srg(self):
        data = self.parse('PK: . example\nCL: a net/minecraft/Test\nMD: a/b (La;)V net/minecraft/Test/start (Lnet/minecraft/Test;)V\nFD: a/c net/minecraft/Test/value\n')
        self.assertEqual(data['methods'][0]['descriptor'], '(La;)V')
        self.assertIsNone(data['fields'][0]['descriptor'])

    def test_conflict_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.parse('CL: a A\nCL: a B\n')

    def test_review_decision_survives_json(self):
        data = self.parse('{"classes":[{"from":"A","to":"B","approved":false}]}')
        self.assertFalse(data['classes'][0]['approved'])

    def test_nonboolean_approval_rejected(self):
        with self.assertRaisesRegex(ValueError, 'approved'):
            self.parse('{"classes":[{"from":"A","to":"B","approved":"false"}]}')

    def test_unsupported_match_session_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            self.parse('Matches saved for two jars')

    def test_mcp_client_csv(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'m.srg').write_text('MD: a/b ()V X/func_1_a ()V\nFD: a/c X/field_2_b\n')
            (p/'methods.csv').write_text('searge,name,side,desc\nfunc_1_a,start,0,test\n')
            (p/'fields.csv').write_text('searge,name,side,desc\nfield_2_b,count,2,test\n')
            result=read(p/'m.srg',p)
            self.assertEqual(result['methods'][0]['to'],'start')
            self.assertEqual(result['fields'][0]['to'],'count')


if __name__ == '__main__': unittest.main()
