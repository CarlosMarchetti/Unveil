"""Internal JSON process protocol; never executes the analyzed binary."""
import json
import sys
from unveil.core.model import InputArtifact, AnalysisContext
from .pe import PeAnalyzer


def main():
    try:
        artifact = InputArtifact.open(sys.argv[1])
        if artifact.type != 'PE':
            raise ValueError('PE worker requires PE input')
        report = PeAnalyzer().analyze(AnalysisContext(artifact, sys.argv[2]))
        print(json.dumps(report, ensure_ascii=True, allow_nan=False))
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
