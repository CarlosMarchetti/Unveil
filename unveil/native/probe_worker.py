"""Internal bounded emulation process; input/output paths supplied by the parent."""
import json
import argparse
from .emulation import probe


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('max_instructions', type=int)
    parser.add_argument('timeout_seconds', type=int)
    parser.add_argument('--model-tsc', action='store_true')
    parser.add_argument('--module-dir', action='append', default=[])
    parser.add_argument('--main-name')
    parser.add_argument('--windows-version')
    parser.add_argument('--debugged', action='store_true')
    args = parser.parse_args()
    try:
        result = probe(args.input, args.output, max_instructions=args.max_instructions,
                       timeout_seconds=args.timeout_seconds, model_tsc=args.model_tsc,
                       module_dirs=args.module_dir, main_name=args.main_name,
                       windows_version=args.windows_version, debugged=args.debugged)
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps(dict(status='blocked', captured=False, reason='backend_error', detail=str(error))))
        raise SystemExit(1)
