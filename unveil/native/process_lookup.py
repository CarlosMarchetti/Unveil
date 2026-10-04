"""Resolve a running process by name so the user does not type PIDs by hand.

This only inspects already-running processes the user started themselves; it
never launches, attaches to, injects into, or otherwise manipulates them.
"""
from pathlib import Path


def find(process_name):
    import psutil
    target = process_name.lower()
    matches = []
    denied = 0
    seen = 0
    for process in psutil.process_iter(['pid', 'name']):
        seen += 1
        try:
            name = process.name()
        except psutil.AccessDenied:
            denied += 1
            continue
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        if name.lower() == target:
            matches.append(process)
    if not matches:
        hint = ('; %d processes were visible but access was denied to their name '
                '(rerun as Administrator if %s should be among them)' % (denied, process_name)
                if denied else '; %d processes visible, none matched' % seen)
        raise ValueError('No running process named ' + process_name + hint)
    if len(matches) > 1:
        pids = ', '.join(str(p.pid) for p in matches)
        raise ValueError('Multiple processes named ' + process_name + ' (pids: ' + pids + '); pass --pid explicitly')
    process = matches[0]
    try:
        exe = process.exe()
    except psutil.AccessDenied:
        raise ValueError('Found pid %d but access to its executable path was denied; rerun as Administrator' % process.pid)
    return dict(pid=process.pid, module_name=process.name(), module_path=Path(exe))