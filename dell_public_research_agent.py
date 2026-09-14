#!/usr/bin/env python3
"""Internet-assisted public Dell suffix research agent.

This agent collects and fingerprints public documentation and source code, then
compares it with local firmware evidence. It intentionally does not generate,
extract, guess, or print BIOS master passwords or bypass keys.
"""
from __future__ import annotations
import argparse, hashlib, json, re, ssl, sys
from pathlib import Path
from urllib.request import Request, urlopen
from dell_3090_fc1b_recovery import analyze

SOURCES = [
    {"name":"dellpwn","url":"https://api.github.com/repos/R3n5k1/dellpwn","kind":"github_metadata"},
    {"name":"dellpwn_default_branch","url":"https://raw.githubusercontent.com/R3n5k1/dellpwn/main/README.md","kind":"public_documentation"},
    {"name":"dellpwn_code_search","url":"https://api.github.com/repos/R3n5k1/dellpwn/contents","kind":"github_tree"},
]
TERMS = ("FC1B", "CF1B", "8FC8", "DVAR", "SIVB", "XOR", "OptiPlex", "3090", "password")

def fetch(url: str, timeout: int = 15) -> tuple[int, bytes, str]:
    req=Request(url, headers={"User-Agent":"Dell-Firmware-Public-Research-Agent/1.0"})
    with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
        return int(getattr(r,"status",200)), r.read(), r.headers.get("content-type","")

def summarize(name: str, url: str, kind: str) -> dict:
    try:
        status, body, content_type=fetch(url)
        text=body.decode("utf-8","replace")
        counts={term:len(re.findall(re.escape(term),text,re.I)) for term in TERMS}
        return {"name":name,"url":url,"kind":kind,"http_status":status,"content_type":content_type,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"term_counts":counts,"error":None}
    except Exception as e:
        return {"name":name,"url":url,"kind":kind,"http_status":None,"bytes":0,"sha256":None,"term_counts":{},"error":f"{type(e).__name__}: {e}"}

def download_public(url: str, directory: Path, limit: int = 128*1024*1024) -> dict:
    """Download one explicitly supplied HTTPS artifact, never execute it."""
    if not url.lower().startswith('https://'):
        return {'url':url,'status':'REJECTED','reason':'HTTPS required'}
    try:
        status, body, content_type=fetch(url, timeout=60)
        if len(body)>limit: return {'url':url,'status':'REJECTED','reason':f'larger than {limit} bytes'}
        digest=hashlib.sha256(body).hexdigest(); name=digest[:16]+'_'+Path(url.split('?',1)[0]).name
        if not Path(name).name or Path(name).name in ('.','..'): name=digest[:16]+'.bin'
        target=directory/name; target.write_bytes(body)
        return {'url':url,'status':'DOWNLOADED','path':str(target),'bytes':len(body),'sha256':digest,'content_type':content_type}
    except Exception as e:
        return {'url':url,'status':'ERROR','reason':f'{type(e).__name__}: {e}'}

def main(argv=None):
    ap=argparse.ArgumentParser(description="Collect public Dell suffix research and compare it with a local dump.")
    ap.add_argument("firmware"); ap.add_argument("--suffix",default="FC1B"); ap.add_argument("--output",default="analysis/public_suffix_research"); ap.add_argument("--source-url",action='append',default=[],help='explicit HTTPS URL to save for offline analysis (repeatable)'); ap.add_argument("--json",action="store_true"); ap.add_argument("--no-modify",action="store_true")
    a=ap.parse_args(argv); p=Path(a.firmware)
    if not p.is_file(): ap.error(f"input not found: {p}")
    suffix=a.suffix.upper().replace("-","")
    if not re.fullmatch(r"[0-9A-F]{4}",suffix): ap.error("--suffix must be four hexadecimal characters")
    out=Path(a.output); out.mkdir(parents=True,exist_ok=True); (out/'sources').mkdir(exist_ok=True)
    local=analyze(p,out)
    sources=[summarize(**s) for s in SOURCES]
    downloads=[download_public(url,out/'sources') for url in a.source_url]
    report={"target":"Dell OptiPlex 3090","suffix":suffix,"local_report":str(out/"report.json"),"sources":sources,"downloaded_artifacts":downloads,"assessment":{"internet_research":"completed with public sources where reachable","algorithm_match":local.get("VERDICT"),"master_password":"NOT_PROVIDED","reason":"Public-source collection cannot prove a private Dell recovery secret; no credential or bypass value is generated.","official_recovery":"Use Dell Support/TechDirect ownership verification when firmware evidence does not independently validate a recoverable construction."},"read_only":True}
    (out/"public_research.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    if a.json: print(json.dumps(report,indent=2,sort_keys=True))
    else: print(f"suffix={suffix} sources={len(sources)} algorithm_match={local.get('VERDICT')} master_password=NOT_PROVIDED report={out/'public_research.json'}")
    return 0
if __name__=='__main__': sys.exit(main())
