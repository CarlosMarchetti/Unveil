"""Explicit live-dump session and optional user-requested executable launch."""
import os
from pathlib import Path
import subprocess
import tempfile
import time

from unveil.core.model import sha256
from unveil.core.reporting import protect_output
from . import live_dump, process_lookup


def run(args, report):
    source = Path(args.input).resolve()
    destination = Path(args.output).resolve()
    protect_output(destination, [source])
    analysis_path = destination.with_suffix('.analysis.exe')
    recovery_path = analysis_path.with_suffix('.recovery.json')
    protected = [source, destination]
    if getattr(args, 'report', None):
        protected.append(args.report)
    protect_output(analysis_path, protected + [recovery_path])
    protect_output(recovery_path, protected + [analysis_path])
    if os.name != 'nt':
        raise ValueError('--dump requires Windows')
    if sha256(source) != report['input']['sha256']:
        raise ValueError('Input changed before live capture')
    launched = None
    result = dict(status='blocked', captured=False, reason='not_attempted',
                  unpacked=False, devirtualized=False, backend='windows-live-dump')
    report['unpacking'] = result
    report['metadataScope'] = 'Original on-disk input; captured bytes are analyzed in recovery.report'
    report['plan']['selection'] = 'windows-live-dump'
    report['importReconstruction'] = dict(status='blocked', reason='live_dump_does_not_reconstruct_imports')
    try:
        if args.launch:
            if source.suffix.lower() != '.exe':
                raise ValueError('--launch requires an EXE input')
            launched = subprocess.Popen([str(source), *args.target_arg], cwd=source.parent,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, shell=False)
            pid = launched.pid
            result.update(launchedByUnveil=True, pid=pid)
        elif args.process_name:
            pid = process_lookup.find(args.process_name)['pid']
        else:
            pid = args.pid
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline:
            if launched and launched.poll() is not None:
                raise ValueError(f'Target exited before capture (exit code {launched.returncode})')
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        if launched and launched.poll() is not None:
            raise ValueError(f'Target exited before capture (exit code {launched.returncode})')
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=destination.name + '.', suffix='.tmp', dir=destination.parent)
        os.close(fd)
        try:
            result.update(live_dump.dump(pid, source, temporary, timeout=args.dump_timeout))
            protect_output(destination, [source])
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        report['status'] = 'partial'
        report['output'] = dict(path=str(destination), sha256=sha256(destination),
                                verified=False, artifactKind='live-mapped-image')
        from .recovery import recover
        try:
            report['recovery'] = recover(destination, analysis_path, result['imageBase'])
            report['recovery']['unreadableRanges'] = result.get('unreadableRanges', [])
        except (OSError, ValueError) as error:
            report['recovery'] = dict(status='blocked', reason=str(error))
    except (OSError, ValueError) as error:
        result.update(status='blocked', captured=False, reason='live_dump_failed', detail=str(error))
        report['status'] = 'blocked'
    finally:
        if launched is not None:
            # The target belongs to the user. Never terminate it after capture.
            result['targetStillRunning'] = launched.poll() is None
            result['pid'] = launched.pid
    return report
