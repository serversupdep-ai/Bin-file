#!/usr/bin/env python3
"""
dell_8fc8_patch.py — unlock Dell BIOS dumps of the newest suffix generations
(8FC8, and its 2025 successor CF1B) where NO public master-password keygen exists.

Background (state of the art, 2024-2026):
  * Suffix families up to E7A8 (+ Latitude-3540 Insyde) have public keygen
    algorithms — see tools/dell_master_keygen.py.
  * 8FC8 and newer (CF1B): the unlock key is derived SERVER-SIDE by Dell
    (support / TechDirect with proof of ownership; some paid sites offer it).
    No public algorithm exists. CVE-2026-40639 (DSA-2026-197) only recovers
    the *user-set* password from DVAR+XOR records on older platforms — it
    does not produce master keys, and SIVB-era platforms are immune.
  * The practical, deterministic unlock used by every repair shop (and by
    paid tools like "Dell 8FC8 BIOS Unlocker" / DellBIOSTools): neutralize the
    DVAR security records in the flash dump so the firmware boots with
    "Service Tag not programmed", you re-enter the Service Tag, and the
    machine comes up password-free (settings reset).

What this tool patches (mirrors the community patcher + this repo's findings):
  1) DVAR security records:  00 FC AA <type> ... / 00 FD AA <type> ...
     -> the subtype byte after the AA magic is zeroed (record = "not set").
  2) SIVB vault record (Security Information Vault Block, found on 2022+
     platforms such as the ARCHES/Precision 3581 dumps in this repo):
     the whole record is erased to 0xFF (clean-flash state). This is exactly
     what the seller's "Patched" 32MB dump in this repo looks like.

Usage:
  python3 dell_8fc8_patch.py --scan  dump.bin          # report only
  python3 dell_8fc8_patch.py --patch dump.bin          # writes dump_unlocked.bin
"""

import re
import sys
import os
import hashlib

FC_RECORD = re.compile(rb'\x00\xfc\xaa(.{1,2})\x00\x00\x00', re.S)
FD_RECORD = re.compile(rb'\x00\xfd\xaa(.{1,2})\x00\x00\x00', re.S)
SIVB_HDR = re.compile(rb'.{4}SIVB', re.S)


def find_sivb_records(d):
    out = []
    for m in re.finditer(rb'SIVB', d):
        o = m.start() - 4
        if o < 0:
            continue
        hdr_len = int.from_bytes(d[o:o + 2], 'little')
        pay_len = int.from_bytes(d[o + 2:o + 4], 'little')
        if 0 < hdr_len < 0x1000 and 0 < pay_len < 0x100000 and o + hdr_len + pay_len <= len(d):
            out.append((o, hdr_len, pay_len))
    return out


def scan(data):
    print("  DVAR FC-records (00 FC AA <type> 000000 ...):")
    hits = 0
    for m in FC_RECORD.finditer(data):
        print(f"    @0x{m.start():08X}  type=0x{m.group(1).hex()}")
        hits += 1
    for m in re.finditer(rb'\x00\xfc\xaa.', data):     # looser: any 00FCAA record
        if not FC_RECORD.match(data[m.start():m.start()+16]):
            print(f"    @0x{m.start():08X}  (loose match, type=0x{m.group(0)[3]:02x} — no 000000 tail)")
            hits += 1
    print("  DVAR FD-records (00 FD AA <type> 000000 ...):")
    for m in FD_RECORD.finditer(data):
        print(f"    @0x{m.start():08X}  type=0x{m.group(1).hex()}")
        hits += 1
    for m in re.finditer(rb'\x00\xfd\xaa.', data):
        if not FD_RECORD.match(data[m.start():m.start()+16]):
            print(f"    @0x{m.start():08X}  (loose match, type=0x{m.group(0)[3]:02x} — no 000000 tail)")
            hits += 1
    print("  SIVB vault records:")
    sivb = find_sivb_records(data)
    for o, hl, pl in sivb:
        blob = data[o:o + hl + pl]
        print(f"    @0x{o:08X}  hdr={hl:#x} payload={pl:#x} sha256={hashlib.sha256(blob).hexdigest()[:32]}...")
    if not sivb:
        print("    (none — vault already absent/erased)")
    return hits, len(sivb)


def patch(data):
    d = bytearray(data)
    changes = []

    # 1) neutralize DVAR FC/FD record subtypes (community 8FC8 patch)
    for pat, name in ((FC_RECORD, "FC"), (FD_RECORD, "FD")):
        for m in pat.finditer(bytes(d)):
            off = m.start()
            if d[off + 3] != 0:
                changes.append((off + 3, d[off + 3], 0, f"DVAR {name} type"))
                d[off + 3] = 0
    # looser variants seen on ARCHES-era dumps (no 000000 tail)
    for pat, name in ((rb'\x00\xfc\xaa', "FC"), (rb'\x00\xfd\xaa', "FD")):
        for m in re.finditer(pat, bytes(d)):
            off = m.start()
            if off + 3 < len(d) and d[off + 3] != 0:
                changes.append((off + 3, d[off + 3], 0, f"DVAR {name} type (loose)"))
                d[off + 3] = 0

    # 2) erase SIVB vault records to clean-flash state (0xFF)
    for o, hl, pl in find_sivb_records(bytes(d)):
        end = min(o + hl + pl + 0x40, len(d))          # incl. trailing metadata
        # erase up to the next 0x200 alignment boundary of non-FF content
        while end < len(d) and d[end] != 0xFF:
            end += 1
        end = (end + 0xFFF) & ~0xFFF
        changes.append((o, "SIVB vault", 0xFF, f"erase 0x{o:X}-0x{end:X}"))
        for i in range(o, min(end, len(d))):
            d[i] = 0xFF

    return bytes(d), changes


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode = "--scan"
    files = []
    for a in args:
        if a in ("--scan", "--patch"):
            mode = a
        else:
            files.append(a)
    for path in files:
        data = open(path, "rb").read()
        print(f"==== {path} ({len(data)//1024} KB)")
        scan(data)
        if mode == "--patch":
            patched, changes = patch(data)
            if not changes:
                print("  nothing to patch (already clean?)")
                continue
            out = os.path.join(os.path.dirname(path) or ".",
                               os.path.splitext(os.path.basename(path))[0] + "_unlocked.bin")
            open(out, "wb").write(patched)
            print(f"  {len(changes)} change(s):")
            for c in changes:
                print(f"    @0x{c[0]:08X}: {c[3]} {c[1] if isinstance(c[1],str) else hex(c[1])} -> {c[2] if c[2]==0xFF else hex(c[2])}")
            print(f"  -> wrote {out}")
            print("  NOTE: after reflashing expect 'Service Tag has not been programmed' —")
            print("        enter the machine's Service Tag, machine reboots password-free.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
