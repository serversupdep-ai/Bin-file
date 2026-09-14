#!/usr/bin/env python3
"""Dell OptiPlex 3090 / FC1B firmware research agent (read-only)."""
from __future__ import annotations
import argparse, json, logging, sys
from pathlib import Path
from dell_3090_fc1b_recovery import analyze

def main(argv=None) -> int:
    ap=argparse.ArgumentParser(description='Analyze an authorized Dell SPI/BIOS dump without modifying it.')
    ap.add_argument('firmware', nargs='?', help='firmware.bin')
    ap.add_argument('--dump', dest='dump_opt', help='firmware dump (alternative to positional input)')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--json', action='store_true', help='print the JSON report to stdout')
    ap.add_argument('--report', help='also copy JSON report to this path')
    ap.add_argument('--output', default='analysis', help='evidence/report directory')
    ap.add_argument('--no-modify', action='store_true', help='explicit read-only mode (default)')
    a=ap.parse_args(argv)
    src=a.dump_opt or a.firmware
    if not src: ap.error('firmware.bin or --dump is required')
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,format='%(levelname)s %(message)s')
    p=Path(src)
    if not p.is_file(): logging.error('input does not exist: %s',p); return 2
    try: r=analyze(p,a.output,a.verbose)
    except (OSError,ValueError) as e: logging.error('analysis failed: %s',e); return 2
    if a.report: Path(a.report).write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    if a.json: print(json.dumps(r,indent=2,sort_keys=True))
    else:
        print(f"VERDICT={r['VERDICT']} RECOVERY_RESULT={r['RECOVERY_RESULT']} CONFIDENCE={r['CONFIDENCE']}")
        print(f"SHA256={r['SHA256']} DVAR={len(r['DVAR_OFFSETS'])} VARIABLES={len(r['CANDIDATE_VARIABLES'])}")
        print(f"Reports: {Path(a.output)/'report.json'} and {Path(a.output)/'report.txt'}")
    return 0
if __name__=='__main__': sys.exit(main())
