import re
import tempfile
import zipfile
from pathlib import Path

from deobf.archive import validate_archive
from deobf.classfile import ClassFile
from deobf import passes
from deobf.writer import build, invoke
from .transforms import registry


def load(context):
    artifact = context.artifact
    classes = {}
    metadata = dict(resources=0, signed=False, multiRelease=False)
    def parse(entry, data):
        try:
            classes[entry] = ClassFile(data, entry)
        except Exception as error:
            context.diagnostics.append(dict(stage='parse', entry=entry, reason=str(error)))
    if artifact.type == 'CLASS':
        if artifact.size > 64 * 1024 * 1024:
            raise ValueError('Class exceeds 64 MiB analysis budget')
        parse(artifact.path.name, artifact.path.read_bytes())
    else:
        with zipfile.ZipFile(artifact.path) as jar:
            for info in validate_archive(jar):
                name = info.filename
                if name.endswith('.class'):
                    parse(name, jar.read(info))
                elif not info.is_dir():
                    metadata['resources'] += 1
                if name.upper() == 'META-INF/MANIFEST.MF':
                    manifest = jar.read(info).decode('utf-8', 'replace')
                    metadata['manifest'] = manifest
                    unfolded = re.sub(r'\r?\n ', '', manifest)
                    metadata['multiRelease'] = bool(re.search(r'^Multi-Release:\s*true\s*$', unfolded, re.I | re.M))
                if re.match(r'^META-INF/(?:[^/]+\.(SF|RSA|DSA|EC)|SIG-[^/]+)$', name, re.I):
                    metadata['signed'] = True
    metadata.update(classes=len(classes), methods=sum(len(c.methods) for c in classes.values()),
                    fields=sum(len(c.fields) for c in classes.values()),
                    strings=sum(sum(bool(v and v[0] == 8) for v in c.cp) for c in classes.values()),
                    classVersions=sorted({c.major for c in classes.values()}),
                    classIndex=[dict(entry=n, name=c.name, super=c.super, interfaces=c.interfaces,
                                     methods=len(c.methods), fields=len(c.fields)) for n, c in sorted(classes.items())])
    return classes, metadata


class JvmAnalyzer:
    id = 'jvm'
    artifact_types = ('JAR', 'CLASS')

    def analyze(self, context):
        classes, metadata = load(context)
        proposed = []
        limitations = ['Detection is heuristic; constant expressions also occur in unobfuscated software.',
                        'Plans describe this input snapshot; later passes can expose more candidates.',
                        'No target classes are loaded or executed. Interpretation models only allowed operations.']
        if context.mode != 'inspect':
            # The legacy interpreter keys classes by internal name, so multiple
            # release variants cannot safely share a transformation model.
            if len({c.name for c in classes.values()}) != len(classes):
                context.diagnostics.append(dict(stage='detect', reason='Duplicate internal names / multi-release variants: detection skipped'))
            else:
                pools, details = passes.discover_pools(classes)
                decryptors = passes.candidates(classes)
                model = dict(classes=classes, pools=pools, decryptors=decryptors)
                for transform in registry().ordered():
                    plans = transform.plan(model)
                    locations = [dict(entry=entry, method=e['method'], descriptor=e['desc'], offset=e['offset'])
                                 for entry, edits in sorted(plans.items()) for e in edits]
                    count = len(locations)
                    confidence = 90 if count else 50
                    evidence = [str(count) + ' statically resolvable replacement sites']
                    if transform.id == 'string-decrypt':
                        evidence.append(str(len(decryptors)) + ' candidate decryptor methods')
                    if count or (transform.id == 'string-decrypt' and decryptors):
                        context.finding('jvm.' + transform.id, evidence, locations, confidence,
                                        recommendedTransformers=[transform.id],
                                        limitations=limitations[:2])
                    proposed.append(dict(id=transform.id, candidates=count,
                                         status='recommended' if count else 'no_candidates'))
                metadata['stringPools'] = details
                metadata['decryptors'] = list(decryptors.values())
        return context.report(metadata, plan=proposed, limitations=limitations)


def verify(context, offline=False):
    classes, metadata = load(context)
    statuses = {}
    if classes:
        runtime = build(download=not offline)
        with tempfile.TemporaryDirectory(prefix='unveil-verify-') as directory:
            work = Path(directory)
            source = context.artifact.path
            if context.artifact.type == 'CLASS':
                source = work / 'input.jar'
                with zipfile.ZipFile(source, 'w') as jar:
                    for name, cls in classes.items():
                        jar.writestr(name, cls.data)
            _, statuses = invoke(runtime, 'verify', source, {name: [] for name in classes}, work)
    for name, (status, reason) in statuses.items():
        if status != 'OK':
            context.diagnostics.append(dict(stage='verify', entry=name, reason=reason))
    report = context.report(metadata, validation=dict(verified=not context.diagnostics,
                            checkedClasses=len(statuses), targetClassesLoaded=False,
                            scope='ASM structural/data-flow verification; not full JVM linkage'))
    if context.diagnostics:
        report['status'] = 'failed'
    return report
