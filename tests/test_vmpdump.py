from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from framework_fixtures import pe_bytes
from unveil.native import vmpdump


class VmpDumpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / 'target.exe'
        self.source.write_bytes(pe_bytes())
        self.backend = Path(temporary.name) / 'backend.exe'
        self.backend.write_bytes(b'fixture only')
        self.output = self.source.with_name('target.VMPDump.exe')

    def run_backend(self):
        return vmpdump.run(self.backend, 123, self.source.name, self.source)

    def test_stale_output_is_never_accepted_or_overwritten(self):
        self.output.write_bytes(b'old evidence')
        with patch.object(subprocess, 'run') as execute:
            result = self.run_backend()
        execute.assert_not_called()
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(self.output.read_bytes(), b'old evidence')

    def test_access_violation_reports_failure(self):
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(
                returncode=0xc0000005, stdout='', stderr='')):
            result = self.run_backend()
        self.assertEqual(result['reason'], 'vmpdump_nonzero_exit')
        self.assertIsNone(result['output'])

    def test_zero_exit_does_not_prove_import_repair(self):
        def execute(*args, **kwargs):
            self.output.write_bytes(pe_bytes())
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(subprocess, 'run', side_effect=execute):
            result = self.run_backend()
        self.assertEqual(result['reason'], 'no_additional_imports_recovered')
        self.assertFalse(result['validation']['runnableVerified'])

    def test_new_non_pe_output_is_rejected(self):
        def execute(*args, **kwargs):
            self.output.write_bytes(b'not a PE')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(subprocess, 'run', side_effect=execute):
            result = self.run_backend()
        self.assertEqual(result['reason'], 'invalid_backend_pe')
