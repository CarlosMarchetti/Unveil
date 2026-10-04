"""Shared string-recovery workflow for JVM and PE, with separate plaintext exports."""
from contextlib import redirect_stdout
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import zipfile

from deobf.archive import validate_archive
from deobf.classfile import ClassFile
from unveil import __version__
from unveil.core.model import InputArtifact, sha256


def visible_strings(data):
    values = []
    for encoding, pattern in [('ascii', rb'[\x20-\x7e]{4,2048}'), ('utf-16le', rb'(?:[\x20-\x7e]\0){4,1024}')]:
        for match in re.finditer(pattern, data):
            values.append(dict(text=match.group().decode(encoding), offset=match.start(), encoding=encoding))
            if len(values) >= 10000:
                return values, True
    return values, False


def class_strings(classes):
    return [dict(text=c.utf(entry[1]), className=c.name, constantIndex=index)
            for c in classes.values() for index, entry in enumerate(c.cp) if entry and entry[0] == 8]


def recover_strings(source, destination, offline=False):
    artifact = InputArtifact.open(source, max_bytes=128 * 1024 * 1024)
    destination = Path(destination).resolve()
    if destination.exists() or not destination.parent.is_dir() or artifact.path.is_relative_to(destination):
        raise ValueError('Choose a new output directory outside the input, with an existing parent.')
    report = dict(tool=dict(name='Unveil', version=__version__), input=artifact.as_dict(),
                  mode='recover-strings', status='completed', targetExecuted=False,
                  recovered=[], visible=[], unresolved=[], limitations=[])
    with tempfile.TemporaryDirectory(prefix='unveil-strings-', dir=destination.parent) as temporary:
        work = Path(temporary) / 'result'
        work.mkdir()
        if artifact.type == 'JAR':
            from unveil.jvm.pipeline import run
            with redirect_stdout(sys.stderr):
                details = run(SimpleNamespace(input=artifact.path, output=work / 'recovered.jar',
                              report=work / 'jvm-report.json', offline=offline, max_iterations=12,
                              transforms=None))
            report['recovered'] = details['decryptedStrings']
            report['unresolved'] = details['unresolved']
            report['decryptors'] = details['decryptors']
            report['validation'] = details['validation']
            report['status'] = details['status']
            report['limitations'] = details['limitations']
            with zipfile.ZipFile(work / 'recovered.jar') as archive:
                classes = {}
                report['visibleErrors'] = []
                for info in validate_archive(archive):
                    if not info.filename.endswith('.class'):
                        continue
                    try:
                        classes[info.filename] = ClassFile(archive.read(info), info.filename)
                    except ValueError as error:
                        report['visibleErrors'].append(dict(entry=info.filename, reason=str(error)))
            report['visible'] = class_strings(classes)
            report['output'] = dict(jar='recovered.jar', sha256=sha256(work / 'recovered.jar'))
        elif artifact.type == 'CLASS':
            from deobf import passes
            c = ClassFile(artifact.path.read_bytes(), artifact.path.name)
            classes = {artifact.path.name: c}
            pools, _ = passes.discover_pools(classes)
            found = passes.candidates(classes)
            plans, report['unresolved'] = passes.decrypt(classes, found, pools)
            report['recovered'] = [edit['decrypted'] for edits in plans.values() for edit in edits]
            report['decryptors'] = list(found.values())
            report['visible'] = class_strings(classes)
            report['limitations'] = ['Standalone CLASS is analyzed without rewriting; use a JAR for verified reconstruction.']
        else:
            from unveil.native.string_patterns import recover
            data = artifact.path.read_bytes()
            report['visible'], report['visibleTruncated'] = visible_strings(data)
            report['recovered'], report['nativeScan'] = recover(data)
            report['limitations'] = list(report['nativeScan']['limitations'])
            report['status'] = 'partial'  # Candidate patterns are not exhaustive decryption.
        report['counts'] = dict(recovered=len(report['recovered']), visible=len(report['visible']),
                                unresolved=len(report['unresolved']))
        report['limitations'].append('Recovery covers supported deterministic patterns, not all strings in every protection.')
        for filename, records, key in [('decrypted-strings.txt', report['recovered'], 'plaintext'),
                                        ('visible-strings.txt', report['visible'], 'text')]:
            # JSON-escaped lines preserve newlines, NULs and lone JVM surrogate characters.
            (work / filename).write_text(''.join(json.dumps(row[key], ensure_ascii=True) + '\n' for row in records), encoding='utf-8')
        if sha256(artifact.path) != artifact.sha256:
            raise ValueError('Input changed during string recovery.')
        (work / 'strings-report.json').write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding='utf-8')
        work.rename(destination)
    report['directory'] = str(destination)
    return report
