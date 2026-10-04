"""New CLI regression against authored fixtures; execute only generated JVM code."""
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from framework_fixtures import class_bytes, pe_bytes


def cli(*args):
    result = subprocess.run([sys.executable, '-m', 'unveil', *map(str, args)],
                            cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=120)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def main():
    work = ROOT / 'test-output/framework'
    work.mkdir(parents=True, exist_ok=True)
    source = work / 'input.jar'
    with zipfile.ZipFile(source, 'w') as jar:
        jar.writestr('Example.class', class_bytes())
        jar.writestr('asset.txt', 'preserved')
    before = source.read_bytes()
    plan = cli('plan', source, '--format', 'json')
    assert plan['plan'][0]['candidates'] == 1
    for name in ('constant', 'string-pool', 'string-decrypt'):
        output = work / (name + '.jar')
        report = cli('deobfuscate', source, '-o', output, '--transform', name, '--offline')
        assert [t['id'] for t in report['transformations']] == [name]
        assert report['output']['verified'], report
        assert report['transformations'][0]['changed'] == (1 if name == 'constant' else 0)
        if name == 'constant':
            assert report['changes'][0]['before'][2]['opcode'] == 96
        assert cli('verify', output, '--format', 'json', '--offline')['validation']['verified']
        with zipfile.ZipFile(output) as jar:
            assert jar.read('asset.txt') == b'preserved'
    assert source.read_bytes() == before
    assert not cli('diff', source, work / 'constant.jar', '--format', 'json')['comparison']['identical']
    full_source = ROOT / 'test-output/fixtures/fixture.jar'
    if not full_source.exists():
        raise AssertionError('Run tests/integration.py first to create the multi-transform fixture')
    combined = cli('deobfuscate', full_source, '-o', work / 'combined.jar', '--offline')
    assert len(combined['legacyDetails']['decryptedStrings']) == 6
    assert combined['output']['verified']
    again = cli('deobfuscate', full_source, '-o', work / 'repeated.jar', '--offline')
    assert combined['output']['sha256'] == again['output']['sha256']
    class_path = work / 'Example.class'
    class_path.write_bytes(class_bytes())
    assert cli('verify', class_path, '--offline', '--format', 'json')['validation']['verified']
    native = work / 'fixture.exe'
    native.write_bytes(pe_bytes())
    assert cli('native', 'imports', native, '--format', 'json')['metadata']['imports']
    assert cli('native', 'strings', native, '--format', 'json')['metadata']['strings']
    print('Framework integration passed: selected/combined transforms, full verification, deterministic JARs, CLASS and PE CLI.')


if __name__ == '__main__':
    main()
