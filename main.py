#!/usr/bin/env python3
"""Compatibility CLI; new framework commands are available via python -m unveil."""
import argparse
from pathlib import Path
import sys
from unveil.jvm.pipeline import run, clean_manifest, archive, log


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('inspect', 'analyze', 'plan', 'deobfuscate', 'unpack', 'verify', 'diff', 'native', 'strings'):
        from unveil.cli import main as framework_main
        return framework_main()
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('input')
    p.add_argument('output',nargs='?',default=None)
    p.add_argument('--report',help='Default: deobf-report.json beside output JAR')
    p.add_argument('--max-iterations',type=int,default=12)
    p.add_argument('--offline',action='store_true',help='Require already downloaded ASM dependencies')
    mode=p.add_mutually_exclusive_group()
    mode.add_argument('--recover-names',action='store_true',help='Analyze names; with output JAR, apply approved mappings')
    mode.add_argument('--apply-mappings',metavar='FILE',help='Apply reviewed JSON/SRG/Tiny mappings atomically')
    p.add_argument('--reference',metavar='JAR',help='Reference JAR for structural matching')
    p.add_argument('--reference-mappings',metavar='FILE',help='Mappings from reference names to readable names')
    p.add_argument('--mcp-dir',metavar='DIR',help='MCP conf directory containing methods.csv and fields.csv')
    p.add_argument('--seed-mappings',metavar='FILE',help='Existing mappings for the target, exported from Matcher or reviewed manually')
    p.add_argument('--names-dir',metavar='DIR',help='Directory for NameRecovery reports and exported mappings')
    p.add_argument('--accept-inferred',action='store_true',help='Approve high-confidence inferred names that pass safety checks')
    args=p.parse_args()
    if not 1<=args.max_iterations<=100: p.error('--max-iterations must be in 1..100')
    try:
        if args.recover_names or args.apply_mappings:
            from deobf.names.cli import run as run_names
            run_names(args)
        else:
            if any((args.reference,args.reference_mappings,args.mcp_dir,args.seed_mappings,args.names_dir,args.accept_inferred)):
                p.error('NameRecovery options require --recover-names or --apply-mappings')
            if args.output is None: args.output=str(Path(args.input).with_name(Path(args.input).stem + '-deobf.jar'))
            run(args)
    except Exception as e:
        log('[!] Failed: '+type(e).__name__+': '+str(e))
        return 1
    return 0


if __name__=='__main__': sys.exit(main())
