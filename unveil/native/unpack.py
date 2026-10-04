import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from unveil.core.engine import analyze
from unveil.core.model import sha256
from unveil.core.reporting import protect_output, write_report
from unveil.native.protection import unpack_plan
from unveil.native import vmpdump as vmpdump_module
from unveil.native import process_lookup


def run(args):
    source = Path(args.input).resolve()
    if getattr(args, 'dump', False) and args.output and not args.report:
        args.report = str(Path(args.output).with_suffix('.dump.json'))
    if args.output:
        protect_output(args.output, [source])
        if Path(args.output).suffix.lower() != '.bin':
            raise ValueError('Memory capture uses RVA layout; use an output ending in .bin')
    if args.report:
        protect_output(args.report, [source] + ([args.output] if args.output else []))
    report = analyze(source, 'inspect')
    if report['input']['type'] != 'PE':
        raise ValueError('unpack currently requires PE input')
    report.update(mode='unpack', status='blocked')
    report['unpacking'] = dict(status='blocked', reason='emulation_opt_in_required',
                               unpacked=False, devirtualized=False)
    report['plan'] = unpack_plan(report['metadata'], vmpdump_configured=bool(getattr(args, 'vmpdump_path', None)))
    if getattr(args, 'dump', False):
        from .dump_session import run as run_dump
        report = run_dump(args, report)
    if args.emulate:
        if not args.output:
            raise ValueError('--emulate requires -o candidate.bin')
        if report['plan']['selection'] is None:
            report['unpacking']['reason'] = 'no_compatible_backend_for_detection'
        elif not all(importlib.util.find_spec(name) for name in ('unicorn', 'capstone')):
            report['unpacking']['reason'] = 'install_requirements_unpack_txt'
        else:
            with tempfile.TemporaryDirectory(prefix='unveil-probe-') as directory:
                snapshot = Path(directory) / 'input.exe'
                shutil.copyfile(source, snapshot)
                if sha256(snapshot) != report['input']['sha256']:
                    raise ValueError('Input changed during analysis')
                capture = Path(directory) / 'candidate.bin'
                try:
                    process = subprocess.run([sys.executable, '-m', 'unveil.native.probe_worker',
                                              str(snapshot), str(capture), str(args.max_instructions), str(args.timeout)]
                                             + (['--model-tsc'] if getattr(args, 'model_tsc', False) else [])
                                             + (['--debugged'] if getattr(args, 'debugged', False) else [])
                                             + ['--main-name', source.name]
                                             + (['--windows-version', args.windows_version]
                                                if getattr(args, 'windows_version', None) else [])
                                             + [part for directory in getattr(args, 'module_dir', [])
                                                for part in ('--module-dir', str(Path(directory).resolve()))],
                                             cwd=Path(__file__).resolve().parents[2], capture_output=True,
                                             text=True, encoding='utf-8', timeout=args.timeout + 10)
                    result = json.loads(process.stdout)
                    if process.returncode and result.get('captured'):
                        raise ValueError('Failed backend cannot publish a capture')
                except subprocess.TimeoutExpired:
                    result = dict(status='blocked', reason='worker_timeout', captured=False)
                except (json.JSONDecodeError, ValueError) as error:
                    result = dict(status='blocked', reason='invalid_worker_response', captured=False, detail=str(error))
                report['unpacking'].update(result)
                if result.get('captured'):
                    size = result['imageSize']
                    if not 0 < size <= 128 * 1024 * 1024 or capture.stat().st_size != size:
                        raise ValueError('Invalid capture size')
                    destination = Path(args.output)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    fd, temporary = tempfile.mkstemp(prefix=destination.name + '.', dir=destination.parent)
                    os.close(fd)
                    try:
                        shutil.copyfile(capture, temporary)
                        os.replace(temporary, destination)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                    report['output'] = dict(path=str(destination.resolve()), sha256=sha256(destination),
                                            verified=False, artifactKind='candidate-mapped-image')
                    report['status'] = 'partial'
    if getattr(args, 'import_fix', False):
        report['importReconstruction'] = dict(status='blocked', reason='not_attempted')
        if not args.vmpdump_path:
            report['importReconstruction'].update(reason='vmpdump_path_not_configured')
        else:
            try:
                if getattr(args, 'dump', False):
                    if not report['unpacking'].get('captured'):
                        raise ValueError('Live capture failed; import reconstruction skipped')
                    pid = report['unpacking']['pid']
                    module, module_path = source.name, source
                elif args.process_name:
                    resolved = process_lookup.find(args.process_name)
                    pid, module, module_path = resolved['pid'], resolved['module_name'], resolved['module_path']
                elif args.pid and args.module:
                    pid, module, module_path = args.pid, args.module, Path(args.module_path or args.module)
                else:
                    raise ValueError('--import-fix requires --process-name, or both --pid and --module')
                result = vmpdump_module.run(args.vmpdump_path, pid, module, module_path=module_path,
                                            entry_point_rva=args.entry_point,
                                            disable_reloc=args.disable_reloc,
                                            timeout_seconds=args.timeout + 55)
                result.setdefault('resolved', dict(pid=pid, module=module, modulePath=str(module_path)))
            except (OSError, ValueError) as error:
                result = dict(status='blocked', reason='invalid_arguments', detail=str(error), output=None)
            report['importReconstruction'] = result
            if result['status'] in ('completed', 'partial'):
                report['status'] = 'partial'
    if args.report:
        write_report(args.report, report, args.format, inputs=[source] + ([args.output] if args.output else []))
    return report
