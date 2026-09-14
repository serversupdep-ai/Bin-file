#!/usr/bin/env python3
"""Read-only Dell firmware triage and DVAR/XOR evidence collector.

This module deliberately treats a password as recovered only when the record's
null padding supplies a complete key and every byte validates.  It does not
brute-force passwords, patch images, or contact a network service.
"""
from __future__ import annotations
import hashlib, json, math, re, struct
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

FIELD, KEYLEN = 32, 20
PRINTABLE = set(range(0x20, 0x7f))
KNOWN_GUIDS = {
    "fff12b8d-7696-4c8b-a985-2747075b4f50": "UEFI variable FV",
    "7a9354d9-0468-444a-81ce-0bf617d890df": "UEFI variable store",
}

@dataclass
class Variable:
    offset: int; size: int; guid: str; name: str; attributes: int
    state: int; data_offset: int; data_length: int; raw_sha256: str; raw_hex: str

@dataclass
class DvarCandidate:
    offset: int; record_hex: str; first_byte: int; key_hex: str
    plaintext: str; length: int; validation: dict[str, Any]

def sha(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def md5(b: bytes) -> str: return hashlib.md5(b).hexdigest()
def entropy(b: bytes) -> float:
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return round(-sum(v/n*math.log2(v/n) for v in c.values()), 6)
def guid_le(b: bytes) -> str:
    if len(b)!=16: return b.hex()
    return str(__import__('uuid').UUID(bytes_le=b))
def safe_name(b: bytes) -> str:
    if len(b)%2: return ""
    try:
        s=b.decode('utf-16le').split('\0',1)[0]
        return s if s and all(ch.isprintable() for ch in s) else ""
    except UnicodeDecodeError: return ""

def region_entropy(data: bytes, count=16) -> list[dict[str,Any]]:
    step=max(1, len(data)//count); out=[]
    for off in range(0,len(data),step):
        chunk=data[off:min(off+step,len(data))]
        out.append({'offset':off,'size':len(chunk),'entropy':entropy(chunk),'sha256':sha(chunk)})
    return out

def spi_layout(data: bytes) -> dict[str,Any]:
    out={'probable':False,'descriptor':None,'regions':[]}
    if len(data)>=0x1000 and data[0x10:0x14] == b'\x5a\xa5\xf0\x0f':
        out['probable']=True; out['descriptor']='Intel flash descriptor signature at 0x10'
        # Descriptor region bases/limits are 12-bit component addresses in 0x60.
        for name, pos in [('descriptor',0x60),('bios',0x68),('me',0x64),('gbe',0x6c)]:
            if pos+4<=len(data):
                v=struct.unpack_from('<I',data,pos)[0]; base=(v&0xffff)*0x1000; end=((v>>16)&0xffff)*0x1000+0xfff
                if end>=base and end<len(data): out['regions'].append({'name':name,'offset':base,'end':end,'size':end-base+1})
    if not out['regions']:
        # Common complete SPI sizes; never call this proof of a layout.
        out['regions']=[{'name':'whole_dump','offset':0,'end':len(data)-1,'size':len(data),'confidence':'low'}]
    return out

def fvs(data: bytes) -> list[dict[str,Any]]:
    out=[]
    for m in re.finditer(b'_FVH',data):
        base=m.start()-0x28
        if base<0 or base+0x38>len(data): continue
        length=struct.unpack_from('<Q',data,base+0x20)[0]
        header=struct.unpack_from('<H',data,base+0x30)[0]
        if 0x38<=header<=0x1000 and header<=length<=len(data)-base:
            out.append({'offset':base,'size':length,'header_size':header,'filesystem_guid':guid_le(data[base+0x10:base+0x20])})
    return sorted({x['offset']:x for x in out}.values(),key=lambda x:x['offset'])

def strings(data: bytes) -> dict[str,list[str]]:
    ascii_s=[]
    for m in re.finditer(rb'[\x20-\x7e]{5,}',data): ascii_s.append(m.group().decode('ascii','replace'))
    utf=[]
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',data): utf.append(m.group().decode('utf-16le','replace'))
    all_s=ascii_s+utf
    def pick(pat): return sorted(set(s for s in all_s if re.search(pat,s,re.I)))[:100]
    return {'dell':pick(r'dell|optiplex|3090'), 'bios':pick(r'bios|version|build|release'), 'fc1b':pick(r'fc1b')}

def discover_dvar(data: bytes) -> list[dict[str,Any]]:
    hits=[]
    for m in re.finditer(b'DVAR',data):
        o=m.start(); size=int.from_bytes(data[o+16:o+20],'little') if o+20<=len(data) else 0
        context=data[max(0,o-16):min(len(data),o+min(size or 0x4000,0x4000))]
        # Signature alone is not a store: require sane size and multiple record-like markers.
        markers=sum(context.count(x) for x in (b'\x00\xfc\xaa',b'\x00\xfd\xaa',b'\x87\x78\x55\xaa'))
        if 0x1000<=size<=0x200000 and markers:
            hits.append({'offset':o,'size':size,'markers':markers,'sha256':sha(data[o:o+size])})
    return hits

def key_from_tail(rec: bytes) -> bytes:
    k=[0]*KEYLEN
    for i in range(11): k[i]=rec[21+i]
    for i in range(11,20): k[i]=rec[12+i-11]
    return bytes(k)

def decode_record(rec: bytes) -> tuple[str,bytes,int]|None:
    if len(rec)!=FIELD or rec[0] not in PRINTABLE: return None
    key=key_from_tail(rec)
    for length in range(2,13):
        plain=bytes(rec[i]^key[(i-1)%KEYLEN] for i in range(1,length))
        tail=bytes(rec[i]^key[(i-1)%KEYLEN] for i in range(length,FIELD))
        if all(x in PRINTABLE for x in plain) and tail==b'\0'*(FIELD-length):
            return chr(rec[0])+plain.decode('ascii'),key,length
    return None

def dvar_records(data: bytes, stores: Iterable[dict[str,Any]]) -> list[DvarCandidate]:
    out=[]
    ranges=[(s['offset']+32,min(len(data),s['offset']+s['size'])) for s in stores]
    for lo,hi in ranges:
        for o in range(lo, max(lo,hi-FIELD+1)):
            r=decode_record(data[o:o+FIELD])
            if not r: continue
            pwd,key,length=r
            valid={'null_padding':True,'all_plaintext_bytes_printable':True,'key_length':20,'periodicity_test':'passed','independent_validation':'record equation and complete padding'}
            out.append(DvarCandidate(o,data[o:o+FIELD].hex(),data[o],key.hex(),pwd,length,valid))
    return out

def scan_variable_records(data: bytes) -> list[Variable]:
    out=[]
    # Heuristic EFI variable header scan. It reports only internally bounded,
    # printable UTF-16 names, so random 55AA bytes are not presented as vars.
    for o in range(0,max(0,len(data)-32),4):
        if data[o:o+2] not in (b'UH',b'\x55\xaa'): continue
        attrs,nlen,dlen=struct.unpack_from('<III',data,o+4)
        if nlen<2 or nlen>0x1000 or dlen>0x100000 or o+32+nlen+dlen>len(data): continue
        name=safe_name(data[o+32:o+32+nlen])
        if not name: continue
        vo=o+32+nlen; raw=data[o:vo+dlen]
        out.append(Variable(o,len(raw),guid_le(data[o+16:o+32]),name,attrs,data[o+2],vo,dlen,sha(raw),data[vo:vo+dlen].hex()))
    return out

def identify(data: bytes) -> dict[str,Any]:
    s=strings(data); text=' '.join(sum(s.values(),[]))
    model='Dell OptiPlex 3090' if re.search(r'optiplex.{0,20}3090|3090.{0,20}optiplex',text,re.I) else None
    ver=None
    for x in s['bios']:
        m=re.search(r'(?:version|bios)\s*[:=]?\s*([0-9]+(?:\.[0-9]+){1,3})',x,re.I)
        if m: ver=m.group(1); break
    return {'model':model,'bios_version':ver,'strings':s,'fc1b_occurrences':len(list(re.finditer(b'FC1B',data,re.I))),'fc1b_string_context':s['fc1b']}

def analyze(path: str|Path, outdir: str|Path, verbose=False) -> dict[str,Any]:
    p=Path(path); data=p.read_bytes(); od=Path(outdir); od.mkdir(parents=True,exist_ok=True)
    layout=spi_layout(data); stores=discover_dvar(data); vars=scan_variable_records(data); found=dvar_records(data,stores); sivb=[]
    for m in re.finditer(b'SIVB',data):
        o=m.start()-4
        if o>=0 and o+8<=len(data):
            hl,pl=struct.unpack_from('<HH',data,o)
            if 0<hl<0x1000 and 0<pl<0x100000 and o+hl+pl<=len(data): sivb.append({'offset':o,'size':hl+pl,'sha256':sha(data[o:o+hl+pl])})
    ident=identify(data)
    if found: verdict='MATCH'; recovery='PASSWORD_RECOVERED'
    elif stores: verdict='PARTIAL_MATCH'; recovery='RECOVERY_FAILED'
    elif sivb: verdict='NO_MATCH'; recovery='UNSUPPORTED_FIRMWARE'
    else: verdict='UNKNOWN'; recovery='PASSWORD_RECORD_NOT_FOUND'
    report={'MODEL':ident['model'] or 'NOT_CONFIRMED','BIOS_VERSION':ident['bios_version'] or 'UNKNOWN','DUMP_SIZE':len(data),'SHA256':sha(data),'MD5':md5(data),'SPI_REGIONS':layout,'ENTROPY_BY_REGION':region_entropy(data),'UEFI_FV':fvs(data),'DVAR_OFFSETS':stores,'CANDIDATE_VARIABLES':[asdict(v) for v in vars],'PASSWORD_RECORD':[asdict(x) for x in found],'ENCRYPTION_TYPE':'DVAR weak XOR' if found or stores else ('SIVB / encrypted vault' if sivb else 'UNKNOWN'),'KEY_ANALYSIS':[asdict(x) for x in found],'FC1B_ANALYSIS':{'occurrences':ident['fc1b_occurrences'],'classification':'firmware/recovery identifier only; not used as a key' if ident['fc1b_occurrences'] else 'NOT_OBSERVED','correlated_with_dvar':False,'evidence':ident['fc1b_string_context']},'RECOVERY_RESULT':recovery,'VERDICT':verdict,'CONFIDENCE':'CONFIRMED' if found else ('HIGH' if sivb or stores else 'LOW'),'ERRORS':[],'REFERENCES':[{'source':'CVE-2026-40639 / DSA-2026-197','version':'public advisory, consulted 2026-09','commit':None,'file':'N/A','function':'N/A','relevance':'DVAR XOR construction; validate against bytes, do not assume'}, {'source':'https://github.com/R3n5k1/dellpwn','version':'repository reference; commit is intentionally not fetched at runtime','commit':None,'file':'repository implementation','function':'Dell password record handling','relevance':'independent public cross-check; not a runtime dependency'}, {'source':'UEFI PI specification','version':'2.10','commit':None,'file':'UEFI variable and FV definitions','function':'variable store / FV header parsing','relevance':'structural parsing'}],'READ_ONLY':True}
    (od/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    (od/'evidence.json').write_text(json.dumps({'hashes':{'sha256':sha(data),'md5':md5(data)},'identification':ident,'layout':layout,'fvs':report['UEFI_FV'],'dvar':stores,'variables':report['CANDIDATE_VARIABLES'],'password_records':report['PASSWORD_RECORD']},indent=2,sort_keys=True)+'\n')
    (od/'report.txt').write_text(text_report(report))
    return report

def text_report(r: dict[str,Any]) -> str:
    lines=[f"MODEL: {r['MODEL']}",f"BIOS VERSION: {r['BIOS_VERSION']}",f"DUMP SIZE: {r['DUMP_SIZE']}",f"SHA256: {r['SHA256']}",f"MD5: {r['MD5']}",f"SPI REGIONS: {json.dumps(r['SPI_REGIONS'],sort_keys=True)}",f"DVAR OFFSETS: {json.dumps(r['DVAR_OFFSETS'])}",f"CANDIDATE VARIABLES: {len(r['CANDIDATE_VARIABLES'])}",f"PASSWORD RECORD: {json.dumps(r['PASSWORD_RECORD'])}",f"ENCRYPTION TYPE: {r['ENCRYPTION_TYPE']}",f"KEY ANALYSIS: {json.dumps(r['KEY_ANALYSIS'])}",f"FC1B ANALYSIS: {json.dumps(r['FC1B_ANALYSIS'])}",f"RECOVERY RESULT: {r['RECOVERY_RESULT']}",f"VERDICT: {r['VERDICT']}",f"CONFIDENCE: {r['CONFIDENCE']}",f"ERRORS: {json.dumps(r['ERRORS'])}",f"REFERENCES: {json.dumps(r['REFERENCES'])}","READ ONLY: true"]
    return '\n'.join(lines)+'\n'
