"""Validate declarations, inheritance families and indirect-name constraints."""
from collections import defaultdict
import re
import zipfile
from .mappings import empty, key, remap_descriptor


def valid_name(name, class_name=False):
    if not isinstance(name, str) or not name or len(name.encode('utf-8', 'surrogatepass')) > 60000: return False
    if any(ord(c) < 32 for c in name) or any(c in name for c in '.;[<>\\'): return False
    if class_name: return all(x not in ('', '.', '..') for x in name.split('/'))
    return '/' not in name


def validate(index, mappings, accept_inferred=False):
    selected, issues = empty(), []
    declared = {'methods': index.methods, 'fields': index.fields}
    string_literals = set().union(*index.strings.values()) if index.strings else set()
    dynamic_names = set()
    native_owners, reflection_owners = set(), set()
    for c in index.classes.values():
        if any(m.access & 0x100 for m in c.methods): native_owners.add(c.name)
        for o, n, d in index.calls[c.name]:
            if o.startswith(('java/lang/reflect/', 'java/lang/invoke/MethodHandles')) or (o == 'java/lang/Class' and n.startswith(('getDeclared', 'getMethod', 'getField', 'forName'))) or n in ('loadClass', 'defineClass'):
                reflection_owners.add(c.name)
        for cp in c.cp:
            if cp and cp[0] in (17, 18):
                nt = c.cp[cp[1][1]][1]
                dynamic_names.add(c.utf(nt[0]))
    related = {n: index.ancestors(n) for n in index.classes}
    local_names = set(index.classes)
    descendants = defaultdict(set)
    for child, parents in related.items():
        for parent in parents: descendants[parent].add(child)
    virtual_signatures = defaultdict(list)
    for (owner, name, desc), method in index.methods.items():
        if not method.access & (2 | 8):
            virtual_signatures[(name, desc.split(')')[0])].append((owner, name, desc))
    serial = {n for n in index.classes if {'java/io/Serializable', 'java/io/Externalizable', 'java/lang/Enum'} & (related[n] | {n})}
    pinned_classes = native_owners | reflection_owners | serial
    # Preserve names mentioned in arbitrary resources. Manifest and service
    # metadata have explicit adapters and are handled at publication time.
    resource_names = set()
    with zipfile.ZipFile(index.path) as z:
        for info in z.infolist():
            if info.filename.endswith('.class') or info.is_dir(): continue
            if info.filename.upper() == 'META-INF/MANIFEST.MF' or info.filename.startswith('META-INF/services/'): continue
            if info.file_size > 4 * 1024 * 1024: continue
            try: text = z.read(info).decode('utf-8')
            except UnicodeError: continue
            resource_names.update(re.findall(r'[\w$]+(?:[./][\w$]+)+', text))
    def reject(kind, item, reason):
        issues.append({'kind': kind, 'mapping': dict(item), 'reason': reason})
    for kind in ('classes', 'methods', 'fields'):
        seen = {}
        for original in mappings[kind]:
            item = dict(original)
            approved = item.get('approved', True) or (accept_inferred and item.get('origin') == 'inferred' and item.get('confidence') == 'high')
            if not approved or item['from'] == item['to']: continue
            item['approved'] = True
            if not valid_name(item['to'], kind == 'classes'):
                reject(kind, item, 'Invalid destination JVM name'); continue
            if kind == 'classes':
                owner = item['from']
                if owner not in index.classes: reject(kind, item, 'Class is absent from input'); continue
                if owner in pinned_classes:
                    reject(kind, item, 'Class participates in native calls, reflection, or Java serialization'); continue
                if owner in string_literals or owner.replace('/', '.') in string_literals:
                    reject(kind, item, 'Class name occurs in a string literal; reflective identity is preserved'); continue
                if owner in resource_names or owner.replace('/', '.') in resource_names:
                    reject(kind, item, 'Class name occurs in a resource without a remapping adapter'); continue
            else:
                owner, name, desc = item.get('owner'), item['from'], item.get('descriptor')
                if desc is None and kind == 'fields':
                    possibilities = [k for k in index.fields if k[:2] == (owner, name)]
                    if len(possibilities) != 1:
                        reject(kind, item, 'SRG field descriptor is ambiguous or field is absent'); continue
                    desc = item['descriptor'] = possibilities[0][2]
                if (owner, name, desc) not in declared[kind]:
                    reject(kind, item, 'Member declaration is absent from input'); continue
                access = index.methods[(owner, name, desc)].access if kind == 'methods' else index.fields[(owner, name, desc)][0]
                if name.startswith('<') or name in ('main', 'serialVersionUID', 'serialPersistentFields', 'readObject', 'writeObject', 'readResolve', 'writeReplace'):
                    reject(kind, item, 'Constructor, entrypoint or serialization hook'); continue
                if owner in pinned_classes or name in string_literals or name in dynamic_names:
                    reject(kind, item, 'Native/reflection/serialization/dynamic-name constraint'); continue
                if kind == 'fields' and (access & 0x4000 or index.classes[owner].access & 0x2000):
                    reject(kind, item, 'Enum or annotation member names are preserved'); continue
                if kind == 'methods' and index.classes[owner].access & 0x2000:
                    reject(kind, item, 'Annotation element names are preserved'); continue
                if item.get('origin') == 'inferred' and not access & 2:
                    reject(kind, item, 'Inferred member names require private visibility for automatic application'); continue
            k = key(kind, item)
            if k in seen:
                if seen[k] != item['to']: reject(kind, item, 'Conflicting destinations for declaration')
                continue
            seen[k] = item['to']; selected[kind].append(item)
    # Virtual methods form families across superclass/interface declarations.
    # Covariant return variants share their source name and parameter descriptor.
    methods = {key('methods', x): x for x in selected['methods']}
    pending = list(methods)
    blocked_families = set()
    while pending:
        source = pending.pop()
        item = methods[source]; method = index.methods[source]
        if method.access & (2 | 8): continue
        owner, name, desc = source
        signature_declarations = virtual_signatures[(name, desc.split(')')[0])]
        declaring_owners = {o for o, n, d in signature_declarations}
        family = [(o, n, d) for o, n, d in signature_declarations
                  if (o == owner or o in related[owner] or owner in related[o]
                      or bool(related[o] & related[owner] & declaring_owners))]
        foreign = {p for k in family for p in related[k[0]] if p not in index.classes and p != 'java/lang/Object'}
        if foreign or any(k[0] in pinned_classes for k in family):
            for k in family: blocked_families.add(k)
            reject('methods', item, 'Virtual method family has an unavailable external ancestor or a pinned class'); continue
        if any(k in methods and methods[k]['to'] != item['to'] for k in family):
            blocked_families.update(family)
            reject('methods', item, 'Conflicting names inside an override family'); continue
        for k in family:
            if k not in methods:
                methods[k] = {**item, 'owner': k[0], 'from': k[1], 'descriptor': k[2], 'origin': 'override-propagation'}
                pending.append(k)
    selected['methods'] = [x for k, x in methods.items() if k not in blocked_families]
    classes = {x['from']: x['to'] for x in selected['classes']}
    destinations = defaultdict(list)
    for n in index.classes: destinations[classes.get(n, n)].append(n)
    collisions = {n for ns in destinations.values() if len(ns) > 1 for n in ns}
    for item in list(selected['classes']):
        if item['from'] in collisions:
            selected['classes'].remove(item); reject('classes', item, 'Destination class collision')
    classes = {x['from']: x['to'] for x in selected['classes']}
    # Package-private and protected access may rely on the original package.
    # Refuse a package move unless every class from that original package moves
    # together to the same destination package. This also protects class access.
    package = lambda n: n.rpartition('/')[0]
    groups = defaultdict(set)
    for n in index.classes: groups[package(n)].add(n)
    for item in list(selected['classes']):
        old, new = item['from'], item['to']
        if package(old) != package(new):
            destination_packages = {package(classes.get(n, n)) for n in groups[package(old)]}
            if len(destination_packages) != 1:
                selected['classes'].remove(item); reject('classes', item, 'Partial package move could break package/protected access; map the entire package together')
    classes = {x['from']: x['to'] for x in selected['classes']}
    # Detect duplicate declarations and accidental new hiding/overriding.
    for kind, table in declared.items():
        chosen = {key(kind, x): x for x in selected[kind]}
        sigs = defaultdict(list)
        for owner, name, desc in table:
            new = chosen.get((owner, name, desc), {}).get('to', name)
            sigs[(owner, new, remap_descriptor(desc, classes))].append((owner, name, desc))
        bad = {k for ks in sigs.values() if len(ks) > 1 for k in ks}
        for k, item in chosen.items():
            for parent in related[k[0]] & local_names:
                for other in sigs.get((parent, item['to'], remap_descriptor(k[2], classes)), []):
                    if other[1] != k[1]: bad.update((k, other))
            for child in descendants[k[0]]:
                for other in sigs.get((child, item['to'], remap_descriptor(k[2], classes)), []):
                    if other[1] != k[1]: bad.update((k, other))
        if bad:
            # If one override-family declaration collides, keep the entire family.
            for k in list(bad):
                if kind == 'methods' and k in chosen:
                    bad.update(q for q in chosen if q[1:] == k[1:] and (q[0] == k[0] or q[0] in related[k[0]] or k[0] in related[q[0]]))
            for k in bad:
                if k in chosen: reject(kind, chosen[k], 'Declaration collision or accidental inheritance relationship')
            selected[kind] = [x for k, x in chosen.items() if k not in bad]
    # Materialize inherited reference aliases in Python. ASM only applies maps.
    aliases = {kind: {key(kind, x): x['to'] for x in selected[kind]} for kind in ('methods', 'fields')}
    for c in index.classes.values():
        for cp in c.cp:
            if not cp or cp[0] not in (9, 10, 11): continue
            owner = c.cls(cp[1][0]); nt = c.cp[cp[1][1]][1]
            name, desc = c.utf(nt[0]), c.utf(nt[1])
            kind = 'fields' if cp[0] == 9 else 'methods'
            definition = index.resolve(owner, name, desc, kind)
            if definition in aliases[kind]: aliases[kind][(owner, name, desc)] = aliases[kind][definition]
    return selected, issues, aliases
