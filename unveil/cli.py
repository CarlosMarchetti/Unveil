import argparse
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

from unveil.core.engine import analyze
from unveil.core.model import InputArtifact, AnalysisContext
from unveil.core.reporting import protect_output, render, write_report


def deobfuscate(args):
    from unveil.jvm.pipeline import run
    artifact = InputArtifact.open(args.input)
    if artifact.type != 'JAR':
        raise ValueError('Deobfuscation currently requires a JAR; CLASS supports inspect/analyze/plan/verify')
    destination = Path(args.output).resolve()
    report_path = Path(args.report).resolve() if args.report else destination.with_suffix('.report.json')
    protect_output(destination, [artifact.path])
    protect_output(report_path, [artifact.path, destination])
    report = analyze(artifact.path, 'plan')
    report['mode'] = 'deobfuscate'
    with tempfile.TemporaryDirectory(prefix='unveil-report-') as directory:
        legacy = run(SimpleNamespace(input=artifact.path, output=destination,
                     report=Path(directory) / 'legacy.json', offline=args.offline,
                     max_iterations=args.max_iterations, transforms=args.transform))
    report['status'] = legacy['status']
    report['output'] = dict(path=str(destination), sha256=legacy['validation']['outputSHA256'],
                            verified=legacy['validation']['allClassesVerified'])
    report['validation'] = legacy['validation']
    report['diagnostics'].extend(legacy['errors'])
    report['changes'] = legacy['changes']
    names = {'constant': 'ConstantDeobf', 'string-pool': 'StringPoolerDeobf', 'string-decrypt': 'StringDecrypt'}
    for name in legacy['selectedTransforms']:
        changed = sum(c['passName'] == names[name] for c in legacy['changes'])
        counts = legacy['transformCounts'].get(names[name], dict(candidates=0, changed=0, failed=0, skipped=0))
        report['transformations'].append(dict(id=name, status='success' if changed else 'unchanged',
                                              **counts,
                                              initialCandidates=next(p['candidates'] for p in report['plan'] if p['id'] == name)))
    report['legacyDetails'] = legacy
    write_report(report_path, report, inputs=[artifact.path, destination])
    return report


def parser():
    root = argparse.ArgumentParser(prog='unveil', description='Static JVM and PE analysis framework')
    commands = root.add_subparsers(dest='command', required=True)
    strings = commands.add_parser('strings', help='Recover supported string patterns; rebuild JARs and export TXT')
    strings.add_argument('input')
    strings.add_argument('-o', '--output', required=True, help='New output directory')
    strings.add_argument('--offline', action='store_true', help='Require local ASM helper dependencies')
    def read_options(command):
        command.add_argument('input')
        command.add_argument('--format', choices=['json', 'text', 'html'], default='text')
        command.add_argument('-o', '--output', help='Report destination; defaults to stdout')
    for name in ('inspect', 'analyze', 'plan', 'verify'):
        command = commands.add_parser(name)
        read_options(command)
        if name == 'verify':
            command.add_argument('--offline', action='store_true')
    command = commands.add_parser('deobfuscate')
    command.add_argument('input')
    command.add_argument('-o', '--output', required=True)
    command.add_argument('--report')
    command.add_argument('--offline', action='store_true')
    command.add_argument('--max-iterations', type=int, choices=range(1, 101), default=12, metavar='1..100')
    command.add_argument('--transform', action='append', choices=['constant', 'string-pool', 'string-decrypt'])
    command = commands.add_parser('unpack', help='Detect protection and optionally probe a candidate mapped image')
    command.add_argument('input')
    command.add_argument('-o', '--output', help='Candidate mapped image (.bin), only written on a capture event')
    command.add_argument('--report', help='Unpacking report destination')
    command.add_argument('--format', choices=['json', 'text', 'html'], default='json')
    command.add_argument('--emulate', action='store_true', help='Opt into bounded CPU emulation; does not start a Windows process')
    command.add_argument('--model-tsc', action='store_true', help='With --emulate, use a synthetic instruction-count RDTSC clock')
    command.add_argument('--module-dir', action='append', default=[],
                         help='Read AMD64 DLLs from this directory into emulator memory; repeat for multiple roots')
    command.add_argument('--windows-version', help='With --emulate, explicit PEB version profile MAJOR.MINOR.BUILD')
    command.add_argument('--debugged', action='store_true', help='With --emulate, set the guest PEB BeingDebugged flag')
    command.add_argument('--dump', action='store_true', help='Explicitly read the main module of a live Windows process into candidate.bin')
    command.add_argument('--launch', action='store_true', help='With --dump, explicitly execute the input EXE; leaves it running after capture')
    command.add_argument('--wait-seconds', type=float, default=2, help='Delay before live capture, 0..60; does not prove unpacking completion')
    command.add_argument('--dump-timeout', type=int, default=30, help='Live read time budget, 1..120 seconds')
    command.add_argument('--target-arg', action='append', default=[], help='Argument for the explicitly launched EXE; repeat or use --target-arg=VALUE')
    command.add_argument('--max-instructions', type=int, default=100_000)
    command.add_argument('--timeout', type=int, default=5, help='Emulation seconds, 1..60')
    command.add_argument('--import-fix', action='store_true',
                         help='Opt into VMPDump import reconstruction against an already-running process')
    command.add_argument('--vmpdump-path', help='Path to a user-supplied, externally verified VMPDump.exe')
    command.add_argument('--process-name', help='Resolve --pid/--module automatically from an already-running process')
    command.add_argument('--pid', type=int, help='Live target PID; for --import-fix the process must already be unpacked')
    command.add_argument('--module', help='Module name as loaded in the target process, per VMPDump usage')
    command.add_argument('--module-path', help='Filesystem path of that module; defaults to --module')
    command.add_argument('--entry-point', help='Entry point RVA in hex, no 0x prefix; forwarded to VMPDump -ep')
    command.add_argument('--disable-reloc', action='store_true', help='Forward VMPDump -disable-reloc')
    command = commands.add_parser('diff')
    read_options(command)
    command.add_argument('other')
    native = commands.add_parser('native').add_subparsers(dest='native_command', required=True)
    for name in ('inspect', 'imports', 'strings'):
        read_options(native.add_parser(name))
    return root


def execute(args):
    if args.command == 'strings':
        from unveil.strings import recover_strings
        return recover_strings(args.input, args.output, args.offline)
    if args.command == 'unpack':
        if args.dump:
            if args.emulate:
                raise ValueError('--dump cannot be combined with --emulate')
            if args.import_fix and (not args.vmpdump_path or not Path(args.vmpdump_path).is_file()):
                raise ValueError('--dump --import-fix requires an existing --vmpdump-path')
            if not args.output or Path(args.output).suffix.lower() != '.bin':
                raise ValueError('--dump requires -o candidate.bin')
            if sum((args.launch, args.pid is not None, bool(args.process_name))) != 1:
                raise ValueError('--dump requires exactly one of --launch, --pid or --process-name')
            if args.pid is not None and not 0 < args.pid <= 0xffffffff:
                raise ValueError('--pid must be a positive 32-bit integer')
            if args.module or args.module_path:
                raise ValueError('--dump captures only the input EXE main module; omit --module/--module-path')
            if not 0 <= args.wait_seconds <= 60 or not 1 <= args.dump_timeout <= 120:
                raise ValueError('Live capture limits: --wait-seconds 0..60, --dump-timeout 1..120')
            if args.target_arg and not args.launch:
                raise ValueError('--target-arg requires --launch')
        elif args.launch or args.target_arg:
            raise ValueError('--launch and --target-arg require --dump')
        from unveil.native.emulation import MAX_INSTRUCTIONS, MAX_TIMEOUT_SECONDS
        if not 1 <= args.max_instructions <= MAX_INSTRUCTIONS or not 1 <= args.timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f'Invalid emulation budgets: instructions 1..{MAX_INSTRUCTIONS}, timeout 1..{MAX_TIMEOUT_SECONDS}')
        if args.model_tsc and not args.emulate:
            raise ValueError('--model-tsc requires --emulate')
        if args.module_dir and not args.emulate:
            raise ValueError('--module-dir requires --emulate')
        if (args.windows_version or args.debugged) and not args.emulate:
            raise ValueError('--windows-version and --debugged require --emulate')
        from unveil.native.windows_environment import parse_windows_version
        parse_windows_version(args.windows_version)
        if len(args.module_dir) > 8 or any(not Path(path).is_dir() for path in args.module_dir):
            raise ValueError('--module-dir requires at most 8 existing directories')
        if args.import_fix and args.vmpdump_path and not args.dump:
            if args.process_name and (args.pid or args.module):
                raise ValueError('--process-name is exclusive with --pid/--module')
            if not args.process_name and (not args.pid or not args.module):
                raise ValueError('--import-fix requires --process-name, or both --pid and --module')
        from unveil.native.unpack import run
        return run(args)
    if args.command == 'deobfuscate':
        return deobfuscate(args)
    if args.output:
        protect_output(args.output, [args.input] + ([args.other] if args.command == 'diff' else []))
    if args.command == 'verify':
        from unveil.jvm.analysis import verify
        artifact = InputArtifact.open(args.input)
        if artifact.type == 'PE':
            report = analyze(args.input, 'inspect')
            report.update(mode='verify', validation=dict(verified=not report['diagnostics'],
                          scope='PE structural inspection; no execution or Authenticode verification'))
            if report['diagnostics']:
                report['status'] = 'failed'
        else:
            report = verify(AnalysisContext(artifact, 'verify'), args.offline)
    elif args.command == 'diff':
        report = analyze(args.input, 'inspect')
        other = analyze(args.other, 'inspect')
        report.update(mode='diff', comparison=dict(input=other['input'],
                      identical=report['input']['sha256'] == other['input']['sha256'],
                      metadataBefore=report['metadata'], metadataAfter=other['metadata'],
                      scope='File hashes and structural metadata; not instruction-level diff'))
        report['diagnostics'].extend(other['diagnostics'])
        if report['diagnostics']:
            report['status'] = 'partial'
    else:
        mode = args.command
        if mode == 'native':
            if InputArtifact.open(args.input).type != 'PE':
                raise ValueError('native commands require PE input')
            mode = 'inspect' if args.native_command == 'inspect' else 'analyze'
        report = analyze(args.input, mode)
        if args.command == 'native':
            report['view'] = args.native_command
    if args.output:
        write_report(args.output, report, args.format, inputs=[args.input] + ([args.other] if args.command == 'diff' else []))
    return report


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        # Helper progress must not contaminate machine-readable stdout.
        with redirect_stdout(sys.stderr):
            report = execute(args)
        print(render(report, getattr(args, 'format', 'json')), end='')
        return 1 if report['status'] == 'failed' else 2 if report['status'] in ('blocked', 'partial', 'completed_with_unresolved') else 0
    except Exception as error:
        print('Unveil: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
