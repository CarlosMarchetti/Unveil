"""Transactional JAR publication: no partial rollback after a global rename."""
import base64
import copy
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile
from ..classfile import ClassFile
from ..writer import build, invoke, ROOT
from .mappings import sha256


def affected(index, mappings, aliases):
    classes = {x['from'] for x in mappings['classes']}
    members = {x['owner'] for kind in ('methods', 'fields') for x in mappings[kind]}
    result = []
    for c in index.classes.values():
        hit = c.name in classes or c.name in members
        for cp in c.cp:
            if hit: break
            if not cp: continue
            if cp[0] == 7:
                text = c.utf(cp[1])
                hit = text in classes or any(n in classes for n in re.findall(r'L([^;]+);', text))
            elif cp[0] == 1:
                hit = any(n in classes for n in re.findall(r'L([^;<]+)[;<]', cp[1]))
            elif cp[0] in (9, 10, 11):
                owner, nt = cp[1]; n, d = c.cp[nt][1]
                ref = (c.cls(owner), c.utf(n), c.utf(d))
                hit = ref in aliases['fields' if cp[0] == 9 else 'methods']
        if hit: result.append(c.entry)
    return sorted(result)


def write_plan(path, mappings, aliases, entries):
    with open(path, 'wb') as f:
        def integer(n): f.write(struct.pack('>i', n))
        def string(s):
            b = s.encode('utf-16-be', 'surrogatepass'); integer(len(b)); f.write(b)
        integer(0x554e4e31)
        integer(len(mappings['classes']))
        for x in mappings['classes']: string(x['from']); string(x['to'])
        for kind in ('methods', 'fields'):
            integer(len(aliases[kind]))
            for (o, n, d), target in sorted(aliases[kind].items()):
                string(o); string(n); string(d); string(target)
        integer(len(entries))
        for entry in entries: string(entry)


def manifest(data, names):
    from main import clean_manifest
    cleaned = clean_manifest(data)
    lines = cleaned.replace(b'\r\n', b'\n').split(b'\n')
    logical = []
    for line in lines:
        if line.startswith(b' ') and logical: logical[-1] += line[1:]
        else: logical.append(line)
    dotted = {a.replace('/', '.'): b.replace('/', '.') for a, b in names.items()}
    result = []
    for line in logical:
        if b': ' in line:
            key, value = line.split(b': ', 1)
            if key.lower() in (b'main-class', b'premain-class', b'agent-class', b'launcher-agent-class'):
                s = value.decode('utf-8'); value = dotted.get(s, s).encode('utf-8')
            elif key.lower() == b'name' and value.endswith(b'.class'):
                s = value[:-6].decode('utf-8'); value = (names.get(s, s) + '.class').encode('utf-8')
            line = key + b': ' + value
        while len(line) > 70:
            result.append(line[:70]); line = b' ' + line[70:]
        result.append(line)
    return b'\r\n'.join(result)


def apply(index, output, mappings, aliases, offline=False):
    source, output = Path(index.path).resolve(), Path(output).resolve()
    if source == output: raise ValueError('NameRecovery never overwrites its input')
    if index.errors: raise ValueError('Cannot remap a JAR with unparsed classes: references could be missed')
    names = {x['from']: x['to'] for x in mappings['classes']}
    entries = affected(index, mappings, aliases)
    output.parent.mkdir(parents=True, exist_ok=True)
    work_root = ROOT / '.work'; work_root.mkdir(exist_ok=True)
    runtime = build(download=not offline)
    with tempfile.TemporaryDirectory(prefix='names-', dir=work_root) as tmp:
        work = Path(tmp); plan = work / 'names.bin'; changes = work / 'changes.zip'
        write_plan(plan, mappings, aliases, entries)
        java, cp = runtime
        process = subprocess.run([java, '-Xmx1g', '-cp', cp, 'NameWriter', str(source), str(plan), str(changes)],
                                 capture_output=True, timeout=600)
        status = {}
        for line in process.stdout.decode('utf-8').splitlines():
            kind, entry, reason = line.split('\t')
            status[base64.b64decode(entry).decode('utf-8')] = (kind, base64.b64decode(reason).decode('utf-8'))
        errors = [{'entry': n, 'reason': why} for n, (kind, why) in status.items() if kind != 'OK']
        if process.returncode or errors or set(status) != set(entries):
            raise ValueError('Name remap transaction rejected; destination unchanged. ' + repr(errors[:5]) + process.stderr.decode('utf-8', 'replace')[:500])
        fd, temporary = tempfile.mkstemp(prefix=output.name + '.', suffix='.tmp', dir=output.parent)
        os.close(fd); temporary = Path(temporary)
        rewritten, resources, removed, published = [], [], [], set()
        try:
            with zipfile.ZipFile(source) as zin, zipfile.ZipFile(changes) as patch, zipfile.ZipFile(temporary, 'w') as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    old, new = info.filename, info.filename
                    data = zin.read(info)
                    if old in status:
                        data = patch.read(old)
                        c = ClassFile(data)
                        new = c.name + '.class'; rewritten.append(new)
                        if c.name != names.get(old[:-6], old[:-6]): raise ValueError('Unexpected class destination')
                    elif old.endswith('.class') and old[:-6] in names:
                        raise ValueError('A renamed declaration was not rewritten')
                    if entries:
                        if re.match(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)$', old, re.I) or old.upper() == 'META-INF/INDEX.LIST':
                            removed.append(old); continue
                        if old.upper() == 'META-INF/MANIFEST.MF':
                            data = manifest(data, names); resources.append(old)
                        elif old.startswith('META-INF/services/') and not info.is_dir():
                            service = old[len('META-INF/services/'):].replace('.', '/')
                            new = 'META-INF/services/' + names.get(service, service).replace('/', '.')
                            lines = []
                            for line in data.decode('utf-8').splitlines(keepends=True):
                                body = line.split('#', 1)[0]
                                token = body.strip()
                                internal = token.replace('.', '/')
                                if internal in names:
                                    line = line.replace(token, names[internal].replace('/', '.'), 1)
                                lines.append(line)
                            replacement = ''.join(lines).encode('utf-8')
                            if replacement != data or new != old: resources.append(old)
                            data = replacement
                    if new in published: raise ValueError('Destination ZIP entry collision: ' + new)
                    published.add(new)
                    meta = copy.copy(info); meta.filename = new; meta.orig_filename = new
                    zout.writestr(meta, data)
            # Reopen the final archive and run ASM checks on exactly the bytes
            # about to be published. No target class loader is involved.
            with zipfile.ZipFile(temporary) as z:
                if z.testzip(): raise ValueError('Output CRC failure')
                for n in rewritten:
                    if ClassFile(z.read(n)).name + '.class' != n: raise ValueError('Output entry/class mismatch')
                with zipfile.ZipFile(source) as original:
                    for info in original.infolist():
                        n = info.filename
                        if n in status or n in removed or n in resources: continue
                        if z.read(n) != original.read(info): raise ValueError('Unrelated entry changed: ' + n)
            _, check = invoke(runtime, 'verify', temporary, {n: [] for n in rewritten}, work)
            if any(kind != 'OK' for kind, why in check.values()): raise ValueError('Final verification failed; destination unchanged')
            result = {'output': str(output), 'modifiedClasses': len(rewritten), 'verifiedClasses': len(check),
                      'outputSHA256': sha256(temporary), 'updatedResources': resources, 'removedSigningMetadata': removed,
                      'atomic': True, 'targetClassesLoaded': False, 'outputReopened': True,
                      'checks': ['Python class parser', 'CheckClassAdapter(dataFlow=true)', 'Analyzer(BasicVerifier)', 'ZIP CRC/resource comparison']}
            os.replace(temporary, output)
            return result
        finally:
            if temporary.exists(): temporary.unlink()
