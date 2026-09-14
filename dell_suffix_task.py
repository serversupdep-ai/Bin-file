"""Suffix-specific evidence and decryption gate for Dell firmware research.

A suffix is an identifier, not an assumed cryptographic key. This module only
returns a decryptable/recoverable result when the dump contains an independently
validated record. It never contacts Dell services, brute-forces values, or
modifies the input image.
"""
from __future__ import annotations
import re
from typing import Any

KNOWN = {"FC1B": "Dell suffix/recovery identifier (classification requires firmware evidence)",
         "CF1B": "Dell suffix/recovery identifier (classification requires firmware evidence)",
         "8FC8": "Dell suffix/recovery identifier (classification requires firmware evidence)"}

def _utf16_hits(data: bytes, needle: str) -> list[int]:
    n=needle.encode("utf-16le"); return [m.start() for m in re.finditer(re.escape(n),data,re.I)]

def inspect_suffix(data: bytes, suffix: str = "FC1B", dvar_records: list[dict[str,Any]]|None = None) -> dict[str,Any]:
    suffix=suffix.upper().replace("-","")
    ascii_hits=[m.start() for m in re.finditer(re.escape(suffix.encode()),data,re.I)]
    utf_hits=_utf16_hits(data,suffix)
    all_hits=sorted(set(ascii_hits+utf_hits))
    nearby=[]
    for off in all_hits[:64]:
        lo=max(0,off-64); hi=min(len(data),off+len(suffix)*4+64)
        sample=data[lo:hi]
        nearby.append({'offset':off,'encoding':'utf16le' if off in utf_hits else 'ascii','context_hex':sample.hex()})
    records=dvar_records or []
    if records:
        classification='correlated_with_validated_password_record' if all_hits else 'DVAR_record_without_suffix_occurrence'
        decryptability='RECOVERABLE_ONLY_BY_RECORD_VALIDATION'
    elif all_hits:
        classification='observed_identifier_not_a_key'
        decryptability='NOT_DECRYPTED'
    else:
        classification='NOT_OBSERVED'
        decryptability='NOT_APPLICABLE'
    return {'requested_suffix':suffix,'known_family':KNOWN.get(suffix),'ascii_occurrences':ascii_hits,'utf16_occurrences':utf_hits,'classification':classification,'is_key':False,'decryptability':decryptability,'validated_records':len(records),'evidence':nearby,'errors':[]}
