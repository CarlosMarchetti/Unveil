"""Compile authored JVM fixtures and verify TXT plus reconstructed JAR output."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from unveil.strings import recover_strings


def main():
    javac = shutil.which('javac')
    if not javac:
        raise RuntimeError('JDK required for string integration')
    parent = ROOT / 'test-output/strings-integration'
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        work = Path(temporary)
        ciphertext = ''.join(chr(ord(char) ^ 42) for char in 'bare-xor-result')
        literal = ''.join('\\u%04x' % ord(char) for char in ciphertext)
        source = work / 'StringsFixture.java'
        source.write_text('''public class StringsFixture {
          private static String decode(String input) {
            StringBuilder result = new StringBuilder();
            for (char c : input.toCharArray()) result.append((char)(c ^ 42));
            return result.toString();
          }
          public static String result() { return decode("%s"); }
        }''' % literal, encoding='utf-8')
        subprocess.run([javac, '-encoding', 'UTF-8', '--release', '8', '-d', str(work), str(source)], check=True)
        original = work / 'input.jar'
        with zipfile.ZipFile(original, 'w') as archive:
            archive.write(work / 'StringsFixture.class', 'StringsFixture.class')
            archive.writestr('resource.txt', b'preserved')
        report = recover_strings(original, work / 'output', offline=True)
        assert report['counts']['recovered'] == 1, report
        assert report['recovered'][0]['plaintext'] == 'bare-xor-result'
        assert report['validation']['allClassesVerified']
        assert not report['targetExecuted']
        lines = (work / 'output/decrypted-strings.txt').read_text().splitlines()
        assert [json.loads(line) for line in lines] == ['bare-xor-result']
        with zipfile.ZipFile(work / 'output/recovered.jar') as archive:
            assert archive.read('resource.txt') == b'preserved'
        print('Strings integration passed: bare XOR, TXT export, verified JAR and preserved resources.')


if __name__ == '__main__':
    main()
