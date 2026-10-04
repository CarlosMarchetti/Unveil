"""Reference matching and explainable offline semantic suggestions."""
from collections import Counter, defaultdict
from hashlib import sha256
import json
import re
import zipfile
from ..classfile import ClassFile, literal
from ..archive import validate_archive
from ..values import Value, arithmetic, arity
from .mappings import empty, record, key, remap_descriptor


def obfuscated(name):
    leaf = name.rsplit('/', 1)[-1].rsplit('$', 1)[-1]
    return len(leaf) <= 2 or (len(leaf) >= 5 and set(leaf) <= set('Il1i0Oo')) or bool(re.fullmatch(r'(?:func|field)_\d+_\w*', leaf))


class Index:
    def __init__(self, path):
        self.path = path
        self.classes, self.errors = {}, []
        with zipfile.ZipFile(path) as jar:
            infos = validate_archive(jar)
            for info in infos:
                if not info.filename.endswith('.class'): continue
                if info.filename.startswith('META-INF/versions/'):
                    raise ValueError('Multi-release JARs are not supported by NameRecovery')
                if info.file_size > 64 * 1024 * 1024: raise ValueError('Class exceeds analysis size budget')
                try:
                    c = ClassFile(jar.read(info), info.filename)
                    if c.name in self.classes: raise ValueError('Duplicate internal class name')
                    if info.filename != c.name + '.class': raise ValueError('Class entry/internal name mismatch')
                    self.classes[c.name] = c
                except Exception as e: self.errors.append({'entry': info.filename, 'reason': str(e)[:300]})
        self.methods = {(c.name, m.name, m.desc): m for c in self.classes.values() for m in c.methods}
        self.fields = {(c.name, n, d): (a, value) for c in self.classes.values() for a, n, d, value in c.fields}
        self.calls = defaultdict(set)
        self.incoming = Counter()
        self.strings = defaultdict(set)
        for c in self.classes.values():
            for m in c.methods:
                for i in m.insns:
                    if i.op in (182, 183, 184, 185):
                        self.calls[c.name].add(i.arg)
                        self.incoming[i.arg[0]] += 1
                    value = literal(i)
                    if value and value[0] == 'S': self.strings[c.name].add(value[1])

    def ancestors(self, owner):
        seen, todo = set(), [owner]
        while todo:
            n = todo.pop()
            if n in seen: continue
            seen.add(n)
            c = self.classes.get(n)
            if c: todo.extend(x for x in [c.super, *c.interfaces] if x)
        seen.discard(owner)
        return seen

    def resolve(self, owner, name, desc, kind):
        table = self.methods if kind == 'methods' else self.fields
        seen = set()
        def find(n):
            if n in seen: return None
            seen.add(n)
            if (n, name, desc) in table: return n, name, desc
            c = self.classes.get(n)
            if c is None: return None
            parents = [*c.interfaces, c.super] if kind == 'fields' else [c.super, *c.interfaces]
            for parent in parents:
                if parent:
                    found = find(parent)
                    if found: return found
            return None
        return find(owner)


def type_shape(desc, index):
    return re.sub(r'L([^;]+);', lambda m: 'L@;' if m[1] in index.classes else m[0], desc)


def method_fingerprint(method, index):
    stack = []
    # Normalize literal encodings and fold adjacent numeric expressions in both
    # inputs; no target bytecode is executed or modified here.
    for i in method.insns:
        const = literal(i)
        n = arity(i.op)
        if n and not i.boundary and len(stack) >= n and all(x[0] == 'constant' for x in stack[-n:]):
            try:
                value = arithmetic(i.op, [Value(*x[1]) for x in stack[-n:]])
                stack[-n:] = [('constant', value.pair())]
                continue
            except (ValueError, OverflowError): pass
        if const is not None: token = ('constant', const)
        elif i.op in (178, 179, 180, 181, 182, 183, 184, 185):
            owner, name, desc = i.arg
            token = (i.op, '@' if owner in index.classes else owner,
                     '@' if owner in index.classes and not name.startswith('<') else name, type_shape(desc, index))
        elif i.op in (187, 189, 192, 193): token = (i.op, '@' if i.arg in index.classes else i.arg)
        elif i.op in (*range(153, 169), 198, 199): token = (i.op,)
        elif i.op in (170, 171): token = (i.op, sorted(i.arg[1]))
        elif i.op == 186: token = (i.op,)  # Full bootstrap data is not a matching anchor.
        elif i.op == 18: token = (i.op, 'opaque-constant')
        else: token = (i.op, i.arg)
        stack.append(token)
    payload = [method.access & 0x508, type_shape(method.desc, index), stack]
    return sha256(json.dumps(payload, ensure_ascii=True, sort_keys=True).encode()).hexdigest()


def partial_confirmation(votes, reverse_votes, reference_methods, hierarchy_agrees):
    """Require bidirectional exclusivity plus coverage or an independent neighbor.

    Added obfuscator helpers must not dilute the reference coverage denominator.
    Two generic methods or a tied reverse match are never sufficient.
    """
    if not votes or not reverse_votes: return False
    forward = sorted(votes.values(), reverse=True)
    reverse = sorted(reverse_votes.values(), reverse=True)
    support = forward[0]
    if support < 3 or reverse[0] != support: return False
    if len(forward) > 1 and support < 3 * forward[1]: return False
    if len(reverse) > 1 and support < 3 * reverse[1]: return False
    coverage = support / max(reference_methods, 1)
    return (support >= 4 and coverage >= .6) or (hierarchy_agrees and coverage >= .25)


def suggest(target, reference=None, reference_names=None, seeds=None):
    output = empty()
    seen = set()
    matches, ambiguities = [], []
    def add(kind, owner, old, desc, new, origin, confidence, evidence, approved=False):
        item = record(kind, owner, old, desc, new, origin=origin, confidence=confidence,
                      evidence=evidence, approved=approved)
        k = kind, key(kind, item)
        if old != new and k not in seen:
            output[kind].append(item); seen.add(k)
    if seeds:
        for kind in ('classes', 'methods', 'fields'):
            for item in seeds[kind]:
                output[kind].append(dict(item)); seen.add((kind, key(kind, item)))
    tf = {k: method_fingerprint(m, target) for k, m in target.methods.items()}
    paired = {}
    class_names = {}
    if reference:
        rn = reference_names or empty()
        rc = {x['from']: x['to'] for x in rn['classes']}
        rm = {(x['owner'], x['from'], x['descriptor']): x['to'] for x in rn['methods']}
        rf = {(x['owner'], x['from'], x.get('descriptor')): x['to'] for x in rn['fields']}
        fingerprints = {k: method_fingerprint(m, reference) for k, m in reference.methods.items()}
        by_readable = defaultdict(list)
        for n in reference.classes: by_readable[rc.get(n, n)].append(n)
        used = set()
        def pair(t, r, why, confident):
            if t in paired or r in used: return
            paired[t] = (r, confident); used.add(r)
            class_names[t] = rc.get(r, r)
            matches.append({'target': t, 'reference': r, 'named': rc.get(r, r), 'evidence': why, 'confidence': 'high' if confident else 'medium'})
            canonical = rc.get(r, r)
            destination = (t.rpartition('/')[0] + '/' if '/' in t else '') + canonical.rsplit('/', 1)[-1]
            add('classes', None, t, None, destination, 'reference', 'high' if confident else 'medium',
                why + ['Reference name: ' + canonical, 'Original package retained for access safety'], confident)
        # Existing meaningful names and explicit class mappings seed the graph.
        for t in sorted(target.classes):
            readable = next((x['to'] for x in (seeds or empty())['classes'] if x['from'] == t), t)
            rs = by_readable.get(readable, [])
            if len(rs) == 1 and (not obfuscated(t) or readable != t): pair(t, rs[0], ['Matching retained/imported class name'], True)
        def class_signature(c, idx, fp):
            methods = sorted(fp[(c.name, m.name, m.desc)] for m in c.methods)
            fields = sorted((a & 0x18, type_shape(d, idx)) for a, n, d, v in c.fields)
            return json.dumps([c.access & 0x6600, len(c.interfaces), fields, methods])
        ti, ri = defaultdict(list), defaultdict(list)
        for n, c in target.classes.items(): ti[class_signature(c, target, tf)].append(n)
        for n, c in reference.classes.items(): ri[class_signature(c, reference, fingerprints)].append(n)
        for signature, ts in ti.items():
            rs = ri.get(signature, [])
            if len(ts) == len(rs) == 1 and sum(len(m.insns) for m in target.classes[ts[0]].methods) >= 12:
                pair(ts[0], rs[0], ['Unique normalized class fingerprint: fields and all method bodies'], True)
        # Small interfaces/getter classes need a previously matched neighbor;
        # their own short instruction sequences alone are not strong anchors.
        for _ in range(8):
            before = len(paired)
            for signature, ts in ti.items():
                rs = ri.get(signature, [])
                if len(ts) != 1 or len(rs) != 1 or ts[0] in paired or rs[0] in used: continue
                t, r = ts[0], rs[0]
                tc, refc = target.classes[t], reference.classes[r]
                anchored = tc.super in paired and paired[tc.super][0] == refc.super
                if not anchored:
                    for neighbor, (rnbr, strong) in list(paired.items()):
                        if not strong: continue
                        if (t in target.classes[neighbor].interfaces and r in reference.classes[rnbr].interfaces) or (
                            any(o == t for o, n, d in target.calls[neighbor]) and any(o == r for o, n, d in reference.calls[rnbr])):
                            anchored = True; break
                if anchored: pair(t, r, ['Unique normalized class fingerprint', 'Hierarchy/call neighbor already matched'], True)
            if len(paired) == before: break
        # Partial matches tolerate added obfuscator helpers, but require review.
        t_methods, r_methods = defaultdict(list), defaultdict(list)
        for k, fp in tf.items():
            if len(target.methods[k].insns) >= 8: t_methods[fp].append(k)
        for k, fp in fingerprints.items():
            if len(reference.methods[k].insns) >= 8: r_methods[fp].append(k)
        votes = defaultdict(Counter)
        for fp, keys in t_methods.items():
            refs = r_methods.get(fp, [])
            if len(keys) == len(refs) == 1: votes[keys[0][0]][refs[0][0]] += 1
        for t, candidates in sorted(votes.items()):
            if t in paired: continue
            ranked = candidates.most_common(3)
            if ranked[0][1] >= 2 and (len(ranked) == 1 or ranked[0][1] >= 2 * ranked[1][1]):
                pair(t, ranked[0][0], [str(ranked[0][1]) + ' globally unique matching method bodies; class may differ'], False)
            elif ranked: ambiguities.append({'target': t, 'candidates': [{'reference': r, 'matchingMethods': n} for r, n in ranked]})
        # Whole-class equality rejects otherwise unchanged Minecraft classes
        # containing injected decryptors/pools. Confirm partial matches using
        # independent, globally unique bodies and bidirectional competition.
        reverse_votes = defaultdict(Counter)
        for t, candidates in votes.items():
            for r, count in candidates.items(): reverse_votes[r][t] = count
        promoted = {}
        for t, (r, confident) in list(paired.items()):
            if confident: continue
            tc, refc = target.classes[t], reference.classes[r]
            # A matched non-Object ancestor is useful independent evidence.
            hierarchy = tc.super in paired and paired[tc.super][0] == refc.super
            hierarchy = hierarchy or any(p in paired and paired[p][0] in refc.interfaces for p in tc.interfaces)
            eligible = sum(len(m.insns) >= 8 for m in refc.methods)
            if votes[t] and votes[t].most_common(1)[0][0] == r and reverse_votes[r].most_common(1)[0][0] == t and partial_confirmation(votes[t], reverse_votes[r], eligible, hierarchy):
                support = votes[t][r]
                evidence = ['Bidirectional unique-method vote winner with >=3x competitor margin',
                            '%d independent method bodies / %d nontrivial reference methods' % (support, eligible)]
                if hierarchy: evidence.append('Superclass/interface correspondence agrees')
                promoted[t] = evidence
                paired[t] = (r, True)
        for match in matches:
            if match['target'] in promoted:
                match['confidence'] = 'high'; match['evidence'].extend(promoted[match['target']])
        for item in output['classes']:
            if item['from'] in promoted and item.get('origin') == 'reference':
                item.update(confidence='high', approved=True)
                item['evidence'].extend(promoted[item['from']])
        for t, (r, confident) in sorted(paired.items()):
            tc, refc = target.classes[t], reference.classes[r]
            methods = defaultdict(list)
            for m in refc.methods: methods[fingerprints[(r, m.name, m.desc)]].append(m)
            for m in tc.methods:
                if m.name.startswith('<'): continue
                candidates = methods.get(tf[(t, m.name, m.desc)], [])
                # Repeated getters/delegators cannot establish member identity.
                count = sum(tf[(t, x.name, x.desc)] == tf[(t, m.name, m.desc)] for x in tc.methods)
                if len(candidates) == count == 1:
                    refm = candidates[0]; name = rm.get((r, refm.name, refm.desc), refm.name)
                    if not obfuscated(name):
                        add('methods', t, m.name, m.desc, name, 'reference', 'high' if confident else 'medium',
                            ['Unique normalized method body in paired class', 'Reference: ' + r + '.' + refm.name + refm.desc], confident)
            # A field needs a unique access pattern across matched method bodies.
            def field_patterns(c, idx, fp):
                patterns = defaultdict(list)
                for method in c.methods:
                    for pos, ins in enumerate(method.insns):
                        if ins.op in (178, 179, 180, 181) and ins.arg[0] == c.name:
                            patterns[ins.arg].append((fp[(c.name, method.name, method.desc)], ins.op))
                result = defaultdict(list)
                for access, name, desc, val in c.fields:
                    p = patterns.get((c.name, name, desc), [])
                    if p: result[(access & 0x18, type_shape(desc, idx), tuple(sorted(p)))].append((name, desc))
                return result
            tp, rp = field_patterns(tc, target, tf), field_patterns(refc, reference, fingerprints)
            for signature, fs in tp.items():
                rs = rp.get(signature, [])
                if len(fs) == len(rs) == 1:
                    old, desc = fs[0]; refname, refdesc = rs[0]
                    new = rf.get((r, refname, refdesc), rf.get((r, refname, None), refname))
                    if not obfuscated(new): add('fields', t, old, desc, new, 'reference', 'high' if confident else 'medium', ['Unique field access pattern in paired method bodies'], confident)
    # Offline semantic rules. These are inferred names, never original names.
    for c in target.classes.values():
        suffix = sha256(c.name.encode()).hexdigest()[:6]
        calls = {(o, n) for o, n, d in target.calls[c.name]}
        words = set(re.findall(r'[a-z]{3,}', ' '.join(target.strings[c.name]).lower()))
        parents = {class_names.get(p, p).rsplit('/', 1)[-1].lower() for p in target.ancestors(c.name)}
        role, evidence = None, []
        if any('guiscreen' in p for p in parents) and {'login', 'password'} <= words:
            role, evidence = 'LoginScreen', ['GuiScreen ancestor', 'Both login and password vocabulary']
        elif ('java/util/Properties', 'load') in calls and any(o.startswith('java/io/') for o, n in calls):
            role, evidence = 'PropertiesStorage', ['Properties.load', 'File/stream operations']
        elif any(o.startswith(('com/google/gson/', 'org/json/')) for o, n in calls) and any(o.startswith('java/io/') for o, n in calls):
            role, evidence = 'JsonStorage', ['JSON API', 'File/stream operations']
        elif ('java/net/URL', 'openConnection') in calls and any(n in ('getInputStream', 'getOutputStream') for o, n in calls):
            role, evidence = 'HttpTransport', ['URL.openConnection', 'Connection stream operations']
        if role and obfuscated(c.name):
            prefix = c.name.rsplit('/', 1)[0] + '/' if '/' in c.name else ''
            add('classes', None, c.name, None, prefix + role + '_' + suffix, 'inferred', 'medium', evidence)
        for m in c.methods:
            if not obfuscated(m.name) or m.name.startswith('<'): continue
            mcalls = {(i.arg[0], i.arg[1]) for i in m.insns if i.op in (182, 183, 184, 185)}
            evidence, name, confidence = [], None, 'medium'
            if m.desc.endswith(')Ljava/lang/String;') and ('java/util/Base64$Decoder', 'decode') in mcalls:
                if ('javax/crypto/Cipher', 'doFinal') in mcalls:
                    name, confidence = 'decryptString', 'high'
                    evidence = ['Returns String', 'Base64.decode and Cipher.doFinal']
                elif any(i.op == 130 for i in m.insns):
                    name, confidence = 'decodeXorString', 'high'; evidence = ['Returns String', 'Base64.decode and IXOR']
            if name:
                member_suffix = sha256((c.name + m.name + m.desc).encode()).hexdigest()[:6]
                add('methods', c.name, m.name, m.desc, name + '_' + member_suffix, 'inferred', confidence, evidence)
        for a, name, desc, val in c.fields:
            if obfuscated(name) and desc == '[Ljava/lang/String;' and a & 8:
                field_suffix = sha256((c.name + name + desc).encode()).hexdigest()[:6]
                add('fields', c.name, name, desc, 'stringPool_' + field_suffix, 'inferred', 'high', ['Static String[] field; role inferred from type'])
    graph = [{'class': c.name, 'super': c.super, 'interfaces': c.interfaces,
              'callsToClasses': sorted({o for o, n, d in target.calls[c.name]}),
              'incomingCalls': target.incoming[c.name], 'stringCount': len(target.strings[c.name])}
             for c in sorted(target.classes.values(), key=lambda c: c.name)]
    return output, {'classMatches': matches, 'ambiguousMatches': ambiguities, 'graph': graph,
                    'semanticEngine': 'deterministic offline rules; no AI service or network requests'}
