import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from framework_fixtures import class_bytes, pe_bytes
from unveil.core.engine import analyze
from unveil.core.model import AnalysisContext, InputArtifact
from unveil.core.registry import Registry
from unveil.core.reporting import protect_output, render
from unveil.native.pe import PeAnalyzer, entropy
from unveil.cli import main


class FrameworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def jar(self):
        path = self.root / 'fixture.jar'
        with zipfile.ZipFile(path, 'w') as jar:
            jar.writestr('Example.class', class_bytes())
            jar.writestr('asset.txt', 'unchanged')
        return path

    def test_class_detection_uses_magic(self):
        path = self.root / 'not-a-class.bin'
        path.write_bytes(class_bytes())
        report = analyze(path)
        self.assertEqual(report['input']['type'], 'CLASS')
        self.assertEqual(report['metadata']['classes'], 1)
        self.assertEqual(report['plan'][0]['id'], 'constant')
        self.assertEqual(report['plan'][0]['candidates'], 1)
        self.assertEqual(report['findings'][0]['locations'][0]['method'], 'answer')

    def test_plan_never_calls_writer_or_changes_input(self):
        path = self.jar()
        before = path.read_bytes()
        with patch('deobf.writer.build', side_effect=AssertionError('Writer must not run')):
            report = analyze(path, 'plan')
        self.assertEqual(report['mode'], 'plan')
        self.assertIsNone(report['output'])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(report, analyze(path, 'plan'))

    def test_invalid_class_partial_report(self):
        path = self.root / 'bad.jar'
        with zipfile.ZipFile(path, 'w') as jar:
            jar.writestr('bad.class', b'bad')
        report = analyze(path)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['diagnostics'][0]['entry'], 'bad.class')

    def test_html_escapes_untrusted_content(self):
        report = analyze(self.jar(), 'inspect')
        report['metadata']['untrusted'] = '</pre><script>alert(1)</script>'
        output = render(report, 'html')
        self.assertNotIn('<script>', output)
        self.assertIn('&lt;script&gt;', output)

    def test_cli_stdout_is_json_and_input_protected(self):
        path = self.jar()
        stdout = io.StringIO()
        with patch('sys.stdout', stdout):
            code = main(['analyze', str(path), '--format', 'json'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())['schemaVersion'], '1.0')
        with patch('sys.stderr', io.StringIO()), patch('sys.stdout', io.StringIO()):
            self.assertEqual(main(['inspect', str(path), '-o', str(path)]), 1)
        self.assertTrue(zipfile.is_zipfile(path))

    def test_hardlink_input_protection(self):
        path = self.jar()
        alias = self.root / 'alias.jar'
        os.link(path, alias)
        with self.assertRaises(ValueError):
            protect_output(alias, [path])

    def test_registry_order_dependencies_and_cycle(self):
        registry = Registry()
        registry.register(SimpleNamespace(id='b', requires=('a',)))
        registry.register(SimpleNamespace(id='a', runs_after=()))
        self.assertEqual([item.id for item in registry.ordered()], ['a', 'b'])
        with self.assertRaisesRegex(ValueError, 'Missing'):
            registry.ordered(['b'])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            registry.register(SimpleNamespace(id='a'))
        with self.assertRaisesRegex(ValueError, 'API'):
            registry.register(SimpleNamespace(id='c'), '2')
        registry.items['a'].runs_after = ('b',)
        with self.assertRaisesRegex(ValueError, 'cycle'):
            registry.ordered()

    def test_pe32_and_pe64_directories(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.root / ('fixture%d.exe' % bits)
                path.write_bytes(pe_bytes(bits))
                report = PeAnalyzer().analyze(AnalysisContext(InputArtifact.open(path)))
                metadata = report['metadata']
                self.assertEqual(metadata['format'], 'PE32+' if bits == 64 else 'PE32')
                self.assertEqual(metadata['imports'][0]['library'], 'KERNEL32.dll')
                self.assertEqual(metadata['imports'][0]['symbols'][0]['name'], 'ExitProcess')
                self.assertEqual(metadata['exports'][0]['name'], 'answer')
                self.assertEqual(metadata['tlsCallbacks'][0]['rva'], 0x1000)
                self.assertEqual(metadata['overlay']['size'], len(b'fixture-overlay'))
                self.assertEqual(report['findings'][0]['id'], 'native.section.rwx')

    def test_native_process_protocol(self):
        path = self.root / 'fixture.exe'
        path.write_bytes(pe_bytes())
        before = path.read_bytes()
        report = analyze(path)
        self.assertEqual(report['input']['type'], 'PE')
        self.assertEqual(path.read_bytes(), before)

    def test_truncated_pe_rejected(self):
        path = self.root / 'truncated.exe'
        for data in [pe_bytes()[:40], pe_bytes()[:150], pe_bytes()[:800]]:
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                PeAnalyzer().analyze(AnalysisContext(InputArtifact.open(path)))

    def test_tls_unbacked_rva_is_diagnostic(self):
        data = bytearray(pe_bytes())
        struct.pack_into('<Q', data, 0x500 + 24, 0x140009000)
        path = self.root / 'tls.exe'
        path.write_bytes(data)
        report = PeAnalyzer().analyze(AnalysisContext(InputArtifact.open(path)))
        self.assertTrue(any(d['stage'] == 'tls' for d in report['diagnostics']))

    def test_entropy_known_values(self):
        self.assertEqual(entropy(b''), 0)
        self.assertEqual(entropy(b'aaaa'), 0)
        self.assertEqual(entropy(bytes(range(256))), 8)

    def test_report_schema(self):
        import jsonschema
        schema = json.loads((Path(__file__).resolve().parents[1] / 'docs/report.schema.json').read_text())
        report = analyze(self.jar(), 'plan')
        jsonschema.validate(report, schema)
        report['findings'][0]['confidence'] = 101
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(report, schema)
