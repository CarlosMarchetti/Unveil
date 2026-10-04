"""JSON, SRG and Tiny v1/v2 import; descriptors always use the source namespace."""
import csv
import hashlib
import json
from pathlib import Path
import re


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def remap_descriptor(desc, classes):
    return re.sub(r'L([^;]+);', lambda m: 'L' + classes.get(m[1], m[1]) + ';', desc)


def empty():
    return {'format': 'unveil-mappings-v1', 'classes': [], 'methods': [], 'fields': []}


def record(kind, owner, name, desc, target, **extra):
    result = {'from': name, 'to': target, 'origin': 'imported', 'confidence': 'reviewed', 'approved': True}
    if kind != 'classes': result.update(owner=owner, descriptor=desc)
    result.update(extra)
    return result


def key(kind, item):
    return item['from'] if kind == 'classes' else (item['owner'], item['from'], item.get('descriptor'))


def read(path, mcp_dir=None):
    path = Path(path)
    text = path.read_text(encoding='utf-8-sig')
    out = empty()
    stripped = text.lstrip()
    if stripped.startswith('{'):
        data = json.loads(text)
        for kind in ('classes', 'methods', 'fields'):
            values = data.get(kind, [])
            if kind == 'classes' and isinstance(values, dict):
                values = [{'from': a, 'to': b} for a, b in values.items()]
            if not isinstance(values, list): raise ValueError('Expected a list for ' + kind)
            for value in values:
                if not isinstance(value, dict): raise ValueError('Mapping entry must be an object')
                item = record(kind, value.get('owner'), value.get('from'), value.get('descriptor'), value.get('to'))
                item.update(value)
                if not isinstance(item.get('approved'), bool): raise ValueError('approved must be true or false')
                if not all(isinstance(item.get(k), str) and item[k] for k in ('from', 'to')):
                    raise ValueError('Mapping from/to must be nonempty strings')
                if kind != 'classes' and not isinstance(item.get('owner'), str): raise ValueError('Missing mapping owner')
                out[kind].append(item)
        if 'sourceSHA256' in data: out['sourceSHA256'] = data['sourceSHA256']
    else:
        lines = [line for line in text.splitlines() if line and not line.startswith('#')]
        if not lines: return out
        head = lines[0].split('\t')
        if head[0] in ('tiny', 'v1'):
            v2 = head[0] == 'tiny'
            if v2 and head[1:3] != ['2', '0']: raise ValueError('Only Tiny 2.0 is supported')
            namespaces = head[3:] if v2 else head[1:]
            if len(namespaces) < 2: raise ValueError('Tiny requires at least two namespaces')
            owner = None
            for line in lines[1:]:
                cols = line.split('\t')
                if v2:
                    if cols[0] == 'c' and len(cols) >= 1 + len(namespaces):
                        owner = cols[1]
                        if cols[len(namespaces)]: out['classes'].append(record('classes', None, owner, None, cols[len(namespaces)]))
                    elif cols[:2] in (['', 'm'], ['', 'f']):
                        if owner is None or len(cols) < 3 + len(namespaces): raise ValueError('Malformed Tiny member')
                        kind = 'methods' if cols[1] == 'm' else 'fields'
                        if cols[2 + len(namespaces)]: out[kind].append(record(kind, owner, cols[3], cols[2], cols[2 + len(namespaces)]))
                    elif cols[:2] == ['', 'escaped-names']:
                        raise ValueError('Tiny escaped-names is not supported; export unescaped names or JSON')
                    # Comments, parameter and local-variable mappings are not applied.
                else:
                    if cols[0] == 'CLASS' and len(cols) == 1 + len(namespaces):
                        if cols[-1]: out['classes'].append(record('classes', None, cols[1], None, cols[-1]))
                    elif cols[0] in ('METHOD', 'FIELD') and len(cols) == 3 + len(namespaces):
                        kind = 'methods' if cols[0] == 'METHOD' else 'fields'
                        if cols[-1]: out[kind].append(record(kind, cols[1], cols[3], cols[2], cols[-1]))
                    else: raise ValueError('Malformed Tiny v1 record')
        else:
            for number, line in enumerate(lines, 1):
                cols = line.split()
                if not cols: continue
                if cols[0] == 'PK:': continue
                if cols[0] == 'CL:' and len(cols) == 3:
                    out['classes'].append(record('classes', None, cols[1], None, cols[2]))
                elif cols[0] in ('MD:', 'FD:') and len(cols) == (5 if cols[0] == 'MD:' else 3):
                    kind = 'methods' if cols[0] == 'MD:' else 'fields'
                    owner, name = cols[1].rsplit('/', 1)
                    target = cols[3 if kind == 'methods' else 2].rsplit('/', 1)[-1]
                    out[kind].append(record(kind, owner, name, cols[2] if kind == 'methods' else None, target))
                else: raise ValueError('Unsupported mapping format/record at line ' + str(number))
    if mcp_dir:
        for kind, filename in [('methods', 'methods.csv'), ('fields', 'fields.csv')]:
            with open(Path(mcp_dir) / filename, newline='', encoding='utf-8-sig') as f:
                rows = list(csv.DictReader(f))
            names = {}
            for row in rows:
                if row.get('side', '0') in ('0', '2'): names[row['searge']] = row['name']
            for item in out[kind]: item['to'] = names.get(item['to'], item['to'])
    seen = {}
    for kind in ('classes', 'methods', 'fields'):
        for item in out[kind]:
            k = kind, key(kind, item)
            if k in seen and seen[k] != item['to']: raise ValueError('Conflicting imported mappings: ' + repr(k))
            seen[k] = item['to']
    return out


def write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')


def write_tiny(path, data):
    lines = ['tiny\t2\t0\tsource\tnamed']
    classes = {x['from']: x['to'] for x in data['classes']}
    owners = set(classes) | {x['owner'] for kind in ('methods', 'fields') for x in data[kind]}
    for owner in sorted(owners):
        lines.append('c\t' + owner + '\t' + classes.get(owner, owner))
        for kind, tag in [('fields', 'f'), ('methods', 'm')]:
            for x in sorted((x for x in data[kind] if x['owner'] == owner), key=lambda x: (x['from'], x['descriptor'])):
                if any(c in value for value in (owner, x['from'], x['to'], x['descriptor']) for c in '\t\r\n\\'):
                    raise ValueError('Names require escaping; use JSON mappings')
                lines.append('\t' + tag + '\t' + x['descriptor'] + '\t' + x['from'] + '\t' + x['to'])
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')
