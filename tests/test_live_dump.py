import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from unveil.cli import main
from unveil.native.live_dump import capture_pages, dump, WindowsProcess
from unveil.native.dump_session import run as run_session


class LiveDumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'image.bin'

    def test_partial_read_records_exact_hole(self):
        def reader(address, size):
            return (b'A' * size, None) if address == 0x1000 else (b'B' * 10, 'partial')
        result = capture_pages(reader, 0x1000, 5000, self.output)
        self.assertEqual(result['bytesRead'], 4106)
        self.assertEqual(result['unreadableRanges'], [dict(rva=4106, size=894, reason='partial')])
        self.assertEqual(self.output.read_bytes(), b'A' * 4096 + b'B' * 10 + bytes(894))
        self.assertFalse(result['completeRead'])

    def test_holes_are_merged_without_claiming_read_bytes(self):
        result = capture_pages(lambda address, size: (b'MZ' if address == 0 else b'', 'noaccess'),
                               0, 8192, self.output)
        self.assertEqual(result['bytesRead'], 2)
        self.assertEqual(result['unreadableRanges'], [dict(rva=2, size=8190, reason='noaccess')])

    def test_completely_unreadable_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'No bytes'):
            capture_pages(lambda address, size: (b'', 'denied'), 0, 4096, self.output)

    def test_deadline_enforced(self):
        with patch('unveil.native.live_dump.time.monotonic', side_effect=[0, 31]):
            with self.assertRaises(TimeoutError):
                capture_pages(lambda a, s: (b'A' * s, None), 0, 4096, self.output)

    def test_cli_launch_requires_explicit_dump_and_destination(self):
        for args in [
            ['--launch'], ['--dump'], ['--dump', '--launch'],
            ['--dump', '--launch', '--pid', '123', '-o', str(self.output)],
            ['--dump', '--pid', '-1', '-o', str(self.output)],
            ['--dump', '--pid', '1', '--emulate', '-o', str(self.output)],
            ['--dump', '--pid', '1', '--target-arg=x', '-o', str(self.output)],
        ]:
            with self.subTest(args=args), patch('sys.stderr', io.StringIO()), patch('sys.stdout', io.StringIO()), \
                    patch('unveil.native.dump_session.subprocess.Popen') as launch:
                self.assertEqual(main(['unpack', 'unused.exe', *args]), 1)
                launch.assert_not_called()

    def test_cli_dump_writes_default_sidecar(self):
        import json
        from framework_fixtures import pe_bytes
        source = Path(self.temp.name) / 'input.exe'
        source.write_bytes(pe_bytes())
        def fake_dump(args, report):
            report['unpacking']['reason'] = 'test_blocked'
            return report
        with patch('unveil.native.dump_session.run', side_effect=fake_dump), patch('sys.stdout', io.StringIO()):
            self.assertEqual(main(['unpack', str(source), '--dump', '--pid', '123',
                                   '-o', str(self.output), '--wait-seconds', '0']), 2)
        sidecar = self.output.with_suffix('.dump.json')
        report = json.loads(sidecar.read_text())
        self.assertEqual(report['unpacking']['reason'], 'test_blocked')
        self.assertIsNone(report['output'])
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows process APIs')
    def test_actual_current_module_read_and_wrong_identity(self):
        result = dump(os.getpid(), sys.executable, self.output)
        self.assertEqual(self.output.read_bytes()[:2], b'MZ')
        self.assertEqual(self.output.stat().st_size, result['imageSize'])
        self.assertEqual(result['bytesRead'] + sum(h['size'] for h in result['unreadableRanges']), result['imageSize'])
        with self.assertRaisesRegex(ValueError, 'does not match'):
            WindowsProcess(os.getpid(), Path(self.temp.name) / 'different.exe')

    @unittest.skipUnless(os.name == 'nt', 'Windows executable launch')
    def test_explicit_launch_captures_authored_child_and_leaves_it_running(self):
        from unveil.core.engine import analyze
        report = analyze(sys.executable, 'inspect')
        report.update(mode='unpack', status='blocked')
        args = SimpleNamespace(input=sys.executable, output=str(self.output), launch=True,
                               target_arg=['-c', 'import time; time.sleep(60)'], wait_seconds=0.5,
                               dump_timeout=30, process_name=None, pid=None)
        children = []
        real_popen = subprocess.Popen

        def launch(*values, **options):
            child = real_popen(*values, **options)
            children.append(child)
            return child

        try:
            with patch('unveil.native.dump_session.subprocess.Popen', side_effect=launch):
                result = run_session(args, report)
            self.assertEqual(result['status'], 'partial', result['unpacking'])
            self.assertTrue(result['unpacking']['targetStillRunning'])
            self.assertFalse(result['unpacking']['unpacked'])
            self.assertFalse(result['output']['verified'])
            self.assertEqual(self.output.read_bytes()[:2], b'MZ')
        finally:
            # These are only the authored children created by this test.
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=10)
