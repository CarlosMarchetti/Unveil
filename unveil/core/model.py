from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
import hashlib

from unveil import __version__


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class InputArtifact:
    path: Path
    type: str
    sha256: str
    size: int

    @classmethod
    def open(cls, path, max_bytes=512 * 1024 * 1024):
        path = Path(path).resolve(strict=True)
        size = path.stat().st_size
        if size > max_bytes:
            raise ValueError('Input exceeds 512 MiB analysis budget')
        with path.open('rb') as stream:
            magic = stream.read(4)
        kind = ('CLASS' if magic == b'\xca\xfe\xba\xbe' else
                'JAR' if magic in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08') else
                'PE' if magic[:2] == b'MZ' else 'ELF' if magic == b'\x7fELF' else 'UNKNOWN')
        if kind in ('UNKNOWN', 'ELF'):
            raise ValueError('Unsupported input format: ' + kind)
        return cls(path, kind, sha256(path), size)

    def as_dict(self):
        return dict(path=str(self.path), type=self.type, sha256=self.sha256, size=self.size)


@dataclass
class AnalysisContext:
    artifact: InputArtifact
    mode: str = 'analyze'
    findings: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)

    def finding(self, id, evidence, locations, confidence=50, severity='info', **extra):
        if not 0 <= confidence <= 100:
            raise ValueError('Confidence must be in 0..100')
        self.findings.append(dict(id=id, severity=severity, confidence=confidence,
                                  evidence=evidence, locations=locations, **extra))

    def report(self, metadata, **extra):
        return dict(schemaVersion='1.0', tool=dict(name='Unveil', version=__version__),
                    input=self.artifact.as_dict(), mode=self.mode,
                    status='partial' if self.diagnostics else 'completed',
                    metadata=metadata, findings=self.findings, diagnostics=self.diagnostics,
                    transformations=[], output=None, **extra)


class Analyzer(Protocol):
    id: str
    artifact_types: tuple

    def analyze(self, context: AnalysisContext) -> dict: ...


class Detector(Protocol):
    id: str

    def detect(self, context: AnalysisContext, model) -> list: ...


class Transformer(Protocol):
    id: str
    requires: tuple
    runs_after: tuple
    runs_before: tuple

    def plan(self, model) -> dict: ...
