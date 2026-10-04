import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deobf.archive import validate_archive
from deobf.names.analysis import Index
from main import run


class ArchiveTests(unittest.TestCase):
    def archive(self, entries):
        jar = Mock()
        jar.infolist.return_value = []
        for name, size in entries:
            info = zipfile.ZipInfo(name)
            info.file_size = size
            jar.infolist.return_value.append(info)
        return jar

    def test_budgets_accept_exact_boundary(self):
        jar = self.archive([('a', 4), ('b', 6)])
        self.assertEqual(len(validate_archive(jar, max_entries=2,
                         max_entry_bytes=6, max_total_bytes=10)), 2)

    def test_reject_before_read(self):
        for entries, limits, message in [
            ([('a', 6), ('b', 6)], {'max_total_bytes': 10}, 'total'),
            ([('a', 7)], {'max_entry_bytes': 6}, 'entry exceeds'),
            ([('a', 0), ('b', 0)], {'max_entries': 1}, 'count'),
            ([('a', 0), ('a', 0)], {}, 'Duplicate'),
        ]:
            with self.subTest(message=message):
                jar = self.archive(entries)
                with self.assertRaisesRegex(ValueError, message):
                    validate_archive(jar, **limits)
                jar.read.assert_not_called()

    def test_encryption_rejected(self):
        jar = self.archive([('a', 1)])
        jar.infolist.return_value[0].flag_bits = 1
        with self.assertRaisesRegex(ValueError, 'Encrypted'):
            validate_archive(jar)

    def test_real_compressed_archive_preserves_metadata(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as jar:
            jar.writestr('resource.txt', b'a' * 1000)
        buffer.seek(0)
        with zipfile.ZipFile(buffer) as jar:
            with self.assertRaisesRegex(ValueError, 'total'):
                validate_archive(jar, max_total_bytes=999)
            infos = validate_archive(jar)
            self.assertEqual(jar.read(infos[0]), b'a' * 1000)

    def test_both_flows_validate_resources_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input.jar'
            source.touch()
            jar = self.archive([('resource.bin', 513 * 1024 * 1024)])
            jar.__enter__ = Mock(return_value=jar)
            jar.__exit__ = Mock(return_value=False)
            args = SimpleNamespace(input=source, output=Path(directory) / 'out.jar', report=None)
            with patch('zipfile.ZipFile', return_value=jar), patch('unveil.jvm.pipeline.build') as build:
                for action in (lambda: Index(source), lambda: run(args)):
                    with self.assertRaisesRegex(ValueError, 'safety limit'):
                        action()
                jar.read.assert_not_called()
                build.assert_not_called()
            self.assertFalse(args.output.exists())
