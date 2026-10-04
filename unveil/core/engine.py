from .model import InputArtifact, AnalysisContext
from .registry import Registry
import json
import subprocess
import sys
from pathlib import Path


def analyzers():
    from unveil.jvm.analysis import JvmAnalyzer
    from unveil.native.pe import PeAnalyzer
    result = Registry()
    result.register(JvmAnalyzer())
    result.register(PeAnalyzer())
    return result


def analyze(path, mode='analyze'):
    context = AnalysisContext(InputArtifact.open(path), mode)
    if context.artifact.type == 'PE':
        process = subprocess.run([sys.executable, '-m', 'unveil.native.worker',
                                  str(context.artifact.path), mode],
                                 capture_output=True, text=True, encoding='utf-8',
                                 cwd=Path(__file__).resolve().parents[2], timeout=60)
        if process.returncode:
            raise ValueError('PE engine failed: ' + process.stderr.strip()[:2000])
        report = json.loads(process.stdout)
        if report['input']['sha256'] != context.artifact.sha256:
            raise ValueError('Input changed while starting the PE engine')
        return report
    for analyzer in analyzers().ordered():
        if context.artifact.type in analyzer.artifact_types:
            return analyzer.analyze(context)
    raise ValueError('No analyzer supports ' + context.artifact.type)
