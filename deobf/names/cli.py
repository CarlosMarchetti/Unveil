"""NameRecovery CLI orchestration and review artifacts."""
from pathlib import Path
from .analysis import Index, suggest, obfuscated
from .mappings import read, empty, write, write_tiny, sha256, key
from .safety import validate
from .remap import apply


def run(args):
    source = Path(args.input).resolve()
    names_dir = Path(args.names_dir).resolve() if args.names_dir else source.parent / 'name-recovery'
    report_path, mapping_path = names_dir / 'name-recovery.json', names_dir / 'mappings.json'
    protected = {source}
    for value in (args.reference, args.reference_mappings, args.apply_mappings, args.seed_mappings):
        if value: protected.add(Path(value).resolve())
    if args.output and Path(args.output).resolve() in protected: raise ValueError('Output overlaps an input/reference/mapping file')
    destinations = {report_path, mapping_path, names_dir / 'approved-mappings.json', names_dir / 'approved-mappings.tiny'}
    if protected & destinations: raise ValueError('Report directory would overwrite an input; choose a different --names-dir')
    if args.output and Path(args.output).resolve() in destinations: raise ValueError('JAR output overlaps a report path')
    print('[NameRecovery] Reading ' + str(source), flush=True)
    target = Index(source)
    if target.errors: raise ValueError('NameRecovery requires all input classes to parse: ' + repr(target.errors[:3]))
    report = {'input': str(source), 'sourceSHA256': sha256(source), 'status': 'analyzing', 'errors': [],
              'limitations': ['Names inferred by rules are not original source identifiers.',
              'Reference fingerprints are structural evidence, not a proof of semantic equivalence.',
              'Reflection/JNI checks are conservative heuristics; external consumers and dynamically constructed names are not fully observable.',
              'Bytecode verification does not constitute a complete JVM linkage/runtime test.']}
    if args.apply_mappings:
        mappings = read(args.apply_mappings)
        if mappings.get('sourceSHA256') and mappings['sourceSHA256'] != report['sourceSHA256']:
            raise ValueError('Mappings belong to a different input SHA-256')
        if not args.output: raise ValueError('--apply-mappings requires an output JAR')
    else:
        reference = Index(args.reference) if args.reference else None
        if reference and reference.errors: raise ValueError('Reference contains unparsed classes')
        reference_names = read(args.reference_mappings, args.mcp_dir) if args.reference_mappings else None
        seeds = read(args.seed_mappings) if args.seed_mappings else None
        if seeds and seeds.get('sourceSHA256') and seeds['sourceSHA256'] != report['sourceSHA256']:
            raise ValueError('Seed mappings belong to a different input')
        if args.reference_mappings and not reference: raise ValueError('--reference-mappings requires --reference')
        if args.mcp_dir and not args.reference_mappings: raise ValueError('--mcp-dir requires --reference-mappings')
        print('[NameRecovery] Comparing references and inferring roles', flush=True)
        mappings, analysis = suggest(target, reference, reference_names, seeds)
        report.update(analysis)
        if reference:
            report['reference'] = {'path': str(Path(args.reference).resolve()), 'sha256': sha256(args.reference), 'classes': len(reference.classes)}
    print('[NameRecovery] Checking inheritance, collisions and indirect references', flush=True)
    approved, blocked, aliases = validate(target, mappings, args.accept_inferred)
    approved.update(sourceSHA256=report['sourceSHA256'])
    mappings.update(sourceSHA256=report['sourceSHA256'])
    report['suggestions'] = mappings
    report['blocked'] = blocked
    report['counts'] = {'inputClasses': len(target.classes),
                        'suggestions': {k: len(mappings[k]) for k in ('classes', 'methods', 'fields')},
                        'approved': {k: len(approved[k]) for k in ('classes', 'methods', 'fields')}, 'blocked': len(blocked)}
    report['counts']['pendingReview'] = {k: sum(not x.get('approved', True) and not (
        args.accept_inferred and x.get('origin') == 'inferred' and x.get('confidence') == 'high')
        for x in mappings[k]) for k in ('classes', 'methods', 'fields')}
    report['counts']['inputMethods'] = len(target.methods)
    report['counts']['inputFields'] = len(target.fields)
    report['counts']['apparentlyObfuscatedClasses'] = sum(obfuscated(n) for n in target.classes)
    report['counts']['matchedClasses'] = len(report.get('classMatches', []))
    write(mapping_path, mappings)
    write(names_dir / 'approved-mappings.json', approved)
    try: write_tiny(names_dir / 'approved-mappings.tiny', approved)
    except ValueError as e: report['tinyExportWarning'] = str(e)
    if args.apply_mappings and blocked:
        report['status'] = 'rejected'; write(report_path, report)
        raise ValueError('Approved mappings contain unsafe/conflicting entries; see ' + str(report_path))
    report['status'] = 'analyzed'
    write(report_path, report)
    if args.output:
        try:
            print('[NameRecovery] Applying approved mappings transactionally', flush=True)
            report['validation'] = apply(target, args.output, approved, aliases, args.offline)
            report['status'] = 'applied'
        except Exception as e:
            report['status'] = 'failed'; report['errors'].append(str(e)); write(report_path, report)
            raise
        write(report_path, report)
    print('[NameRecovery] Approved: ' + str(report['counts']['approved']) + '; blocked: ' + str(len(blocked)), flush=True)
    print('[NameRecovery] Pending review: ' + str(report['counts']['pendingReview']), flush=True)
    print('[NameRecovery] Report: ' + str(report_path), flush=True)
    return report
