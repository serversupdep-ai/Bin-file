#!/usr/bin/env python3
"""Suffix-specific Dell firmware research CLI.

This is an evidence collector, not a guessed master-code generator. It can
identify suffix evidence and delegate complete dump validation to agent.py;
recovery is reported only when a validated byte-level construction is found.
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path
from dell_3090_fc1b_recovery import analyze
from dell_suffix_task import inspect_suffix

def occurrences(data: bytes, suffix: str):
    result=inspect_suffix(data,suffix)
    return result['evidence']

def main(argv=None):
    ap=argparse.ArgumentParser(description='Analyze a Dell BIOS suffix from an authorized dump.')
    ap.add_argument('firmware'); ap.add_argument('--suffix',default='CF1B',help='suffix, e.g. CF1B or 8FC8')
    ap.add_argument('--output',default='analysis/suffix_task'); ap.add_argument('--json',action='store_true')
    ap.add_argument('--no-modify',action='store_true',help='read-only; accepted for explicitness')
    a=ap.parse_args(argv); suffix=a.suffix.upper().replace('-','')
    if len(suffix)!=4 or any(c not in '0123456789ABCDEF' for c in suffix): ap.error('--suffix must be four hexadecimal characters')
    p=Path(a.firmware)
    if not p.is_file(): ap.error(f'input not found: {p}')
    data=p.read_bytes(); base=analyze(p,a.output)
    suffix_evidence=inspect_suffix(data,suffix)
    hits=suffix_evidence['evidence']
    report={'target_suffix':suffix,'dump_size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'occurrences':hits,'classification':suffix_evidence['classification'],'key_relationship': 'not established','decryption': {'status':'NOT_PERFORMED','reason':'No suffix-specific byte-level construction was proven from this dump; no guessed formula or brute force used.'},'base_report':str(Path(a.output)/'report.json'),'read_only':True}
    Path(a.output).mkdir(parents=True,exist_ok=True); (Path(a.output)/'suffix_report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    if a.json: print(json.dumps(report,indent=2,sort_keys=True))
    else: print(f"suffix={suffix} observed={bool(hits)} status={report['decryption']['status']} report={Path(a.output)/'suffix_report.json'}")
    return 0
if __name__=='__main__': sys.exit(main())
