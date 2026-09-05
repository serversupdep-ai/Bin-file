#!/usr/bin/env python3
"""dell_vault_grab.py — stdlib-only Dell BIOS security-vault extractor.

Purpose: given ANY Dell firmware file (BIOS update .exe, BIOS_IMG.rcv recovery
image, full SPI dump .bin, or an extracted volume/module), locate the
DellSecurityVaultSmm module (FFS file C7CAF1C7-2D97-45CB-99D9-D89AAF8ACC11 —
holds the unlock-suffix parameter tables) and print the decoded suffix table
entries as text. No third-party packages needed — pure standard library.

Why: the newest unlock generations (9ABE / CF1B / rotated-E7A8) ship different
parameter tables per BIOS build. If you own such a machine, run this on the
PUBLIC update package for your model from dell.com/support and paste the
output — it contains no personal data (no service tag, no passwords), just
Dell's published firmware tables.

Usage:
    python3 dell_vault_grab.py <firmware-file>            # scan + report
    python3 dell_vault_grab.py <file> --save vault.pe     # also dump module
"""

import argparse
import io
import lzma
import os
import re
import struct
import sys
import zlib

VAULT_FFS = bytes.fromhex("c7caf1c72d9745cb99d9d89aaf8acc11")  # DellSecurityVaultSmm file GUID (LE)
LZMA_GUID = bytes.fromhex("ee4e5898391442599d6edc7bd79403cf")  # LZMA-custom GUIDed section (LE)
ALPHA_PREFIX = b"Q92G0drk9y63r5DG"                             # 72-char alphabet family signature
MAX_BLOB = 256 * 1024 * 1024
MAX_DEPTH = 6

seen_hashes = set()


# --------------------------------------------------------------------------- #
# generic scanning helpers
# --------------------------------------------------------------------------- #

def try_lzma_alone(buf):
    """Try LZMA_ALONE decompression starting exactly at buf."""
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out = d.decompress(buf)
        if len(out) >= 0x1000:
            return out
    except Exception:
        pass
    return None


def find_lzma_streams(data, limit=64):
    """Yield decompressed blobs for plausible LZMA-alone streams in data."""
    out = []
    for m in re.finditer(rb"\x5d\x00\x00", data):
        blob = try_lzma_alone(data[m.start():])
        if blob:
            out.append((m.start(), blob))
            if len(out) >= limit:
                break
    return out


# --------------------------------------------------------------------------- #
# minimal FFS (firmware volume) parser
# --------------------------------------------------------------------------- #

def parse_fv(data, base_off, files_out, depth):
    """Parse one firmware volume at base_off; append (guid, type, payload)."""
    try:
        fv_len = struct.unpack_from("<Q", data, base_off + 0x20)[0]
        hdr_len = struct.unpack_from("<H", data, base_off + 0x30)[0]
        if not (0x48 <= hdr_len <= 0x1000) or fv_len < hdr_len or fv_len > len(data) - base_off:
            return False
    except struct.error:
        return False
    off = base_off + hdr_len
    end = base_off + fv_len
    ok = False
    while off + 24 <= end:
        guid = data[off:off + 16]
        ftype = data[off + 18]
        size = data[off + 20] | (data[off + 21] << 16) | (data[off + 22] << 24)
        if ftype == 0xF0:                                # pad file — skip, keep scanning
            if size < 24:
                break
            off = (off + size + 7) & ~7
            continue
        if guid == b"\xff" * 16 or size in (0, 0xFFFFFF) or off + size > end:
            break                                        # erased/free space
        payload = data[off + 24: off + size]
        files_out.append((guid, ftype, payload))
        ok = True
        if size < 24:
            break
        off = (off + size + 7) & ~7
    return ok


def parse_sections(payload, out, depth):
    """Parse FFS sections; recurse into FV images and GUID-defined (LZMA) sections."""
    off = 0
    while off + 4 <= len(payload):
        size = payload[off] | (payload[off + 1] << 8) | (payload[off + 2] << 16)
        stype = payload[off + 3]
        if size < 4 or off + size > len(payload):
            break
        body = payload[off + 4: off + size]
        if stype == 0x02 and len(body) >= 0x12:          # GUID-defined
            sguid = body[0:16]
            data_off = body[0x10] | (body[0x11] << 8)
            if sguid == LZMA_GUID and depth < MAX_DEPTH:
                blob = try_lzma_alone(body[data_off:])
                if blob:
                    out.append(("lzma-section", blob))
                    scan_blob(blob, out, depth + 1)
            elif depth < MAX_DEPTH and body[data_off:data_off + 2] == b"MZ":
                out.append(("guid-pe32", body[data_off:]))
        elif stype == 0x17 and depth < MAX_DEPTH:        # firmware-volume image
            scan_blob(body, out, depth + 1)
        elif stype == 0x10:                              # PE32
            out.append(("pe32", body))
        elif stype == 0x12:                              # TE image (rare for SMM)
            out.append(("te", body))
        elif stype == 0x15:                              # user-interface name
            try:
                out.append(("ui", body.decode("utf-16-le", "ignore").rstrip("\0")))
            except Exception:
                pass
        off = (off + size + 3) & ~3


def scan_blob(data, out, depth):
    """Find FVs in a blob, parse their files/sections, recurse."""
    for m in re.finditer(rb"_FVH", data):
        base = m.start() - 0x28
        if base < 0:
            continue
        files = []
        if parse_fv(data, base, files, depth):
            for guid, ftype, payload in files:
                out.append(("file", guid.hex(), ftype, payload))
                if ftype in (0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F):
                    parse_sections(payload, out, depth + 1)
            return True
    return False


# --------------------------------------------------------------------------- #
# vault-specific decoding
# --------------------------------------------------------------------------- #

def find_alpha(data):
    offs = [m.start() for m in re.finditer(re.escape(ALPHA_PREFIX), data)]
    return offs


def decode_suffix_table(d, table_off):
    """Decode 24-byte entries {u16 suffix; u16 pad; u32 0; u32 params_va; u32 0; u32 alpha_va}."""
    entries = []
    off = table_off
    while off + 24 <= len(d) and len(entries) < 32:
        suffix, pad, f1, p_params, f2, p_alpha = struct.unpack_from("<HHIIII", d, off)
        if suffix == 0xFFFF:
            entries.append((suffix, None, None, None))
            break
        entries.append((suffix, pad, p_params, p_alpha))
        off += 24
    return entries


KNOWN_SUFFIXES = {0x8FC8, 0xE7A8, 0x9ABE, 0xAB9E, 0xCF1B, 0x3FE2, 0x0001, 0x1F66, 0x1D3B, 0x2A7B}


def _entry(d, o):
    """One 24-byte table entry or None: {u16 suffix; u16 pad; u32 0; u32 params_va; u32 0; u32 alpha_va}."""
    if o < 0 or o + 24 > len(d):
        return None
    suffix, pad, f1, p_params, f2, p_alpha = struct.unpack_from("<HHIIII", d, o)
    if pad != 0 or f1 != 0 or f2 != 0:
        return None
    if p_params not in (0,) and not (0x1000 <= p_params <= 0x200000):
        return None
    if p_alpha not in (0,) and not (0x1000 <= p_alpha <= 0x200000):
        return None
    return suffix, p_params, p_alpha


def find_tables(d):
    """Runs of consecutive valid entries containing >=2 known suffix words (or a lone 9ABE/CF1B)."""
    out = []
    o = 0
    while o + 24 <= len(d):
        run = []
        p = o
        while True:
            e = _entry(d, p)
            if e is None:
                break
            run.append(e)
            if e[0] == 0xFFFF:
                break
            if len(run) >= 16:
                break
            p += 24
        known = sum(1 for e in run if e[0] in KNOWN_SUFFIXES)
        hot = any(e[0] in (0x9ABE, 0xAB9E, 0xCF1B) for e in run)
        if len(run) >= 2 and (known >= 2 or hot):
            out.append((o, run))
            o += 24 * len(run)
        else:
            o += 2
    return out


def pe_sections(d):
    """Return [(name, vaddr, vsize, raw_off, rawsz)] or [] if not a PE."""
    if d[:2] != b"MZ":
        return []
    try:
        e = struct.unpack_from("<I", d, 0x3c)[0]
        if d[e:e + 4] != b"PE\x00\x00":
            return []
        optsz = struct.unpack_from("<H", d, e + 0x14)[0]
        nsec = struct.unpack_from("<H", d, e + 6)[0]
        off = e + 0x18 + optsz
        secs = []
        for _ in range(nsec):
            nm = d[off:off + 8].rstrip(b"\0").decode("latin1")
            vs, va, rs, ra = struct.unpack_from("<IIII", d, off + 8)
            secs.append((nm, va, vs, ra, rs))
            off += 40
        return secs
    except Exception:
        return []


def va2off(secs, va, d=None):
    for nm, v, vs, ra, rs in secs:
        if v <= va < v + max(vs, rs):
            o = ra + (va - v)
            if d is None or o < len(d):
                return o
    return None


def calibrate_delta(d, tables):
    """VA->file delta via the PE section table; fall back to majority vote."""
    secs = pe_sections(d)
    if secs:
        for _, run in tables:
            for suffix, p_params, p_alpha in run:
                if p_alpha:
                    o = va2off(secs, p_alpha, d)
                    if o is not None and d[o:o + 16] == ALPHA_PREFIX[:16]:
                        return p_alpha - o
        # no exact alphabet confirmation: use any mappable pointer
        for _, run in tables:
            for suffix, p_params, p_alpha in run:
                for ptr in (p_alpha, p_params):
                    if ptr:
                        o = va2off(secs, ptr, d)
                        if o is not None:
                            return ptr - o
    from collections import Counter
    votes = Counter()
    alpha_offs = [m.start() for m in re.finditer(re.escape(ALPHA_PREFIX), d)]
    for _, run in tables:
        for suffix, p_params, p_alpha in run:
            if p_alpha:
                for a in alpha_offs:
                    if 0 < p_alpha - a < 0x20000:
                        votes[p_alpha - a] += 1
    return votes.most_common(1)[0][0] if votes else 0x1000


def report_module(d, label, save_path):
    print(f"\n[+] security-vault module: {label} ({len(d)} bytes)")
    if d[:2] == b"MZ":
        print("    (valid PE image)")
    alpha_offs = [m.start() for m in re.finditer(re.escape(ALPHA_PREFIX), d)]
    if alpha_offs:
        print(f"    alphabet(s) at file offset(s): {', '.join(hex(a) for a in alpha_offs[:4])}"
              f" -> {d[alpha_offs[0]:alpha_offs[0]+72].decode('latin1')!r}")

    tables = find_tables(d)
    secs = pe_sections(d)
    if not tables:
        print("    [!] no suffix table found — u16 words of interest:")
        for w in (0x9ABE, 0xAB9E, 0xCF1B, 0x8FCE, 0x8FC8, 0xE7A8, 0x3FE2):
            offs = [m.start() for m in re.finditer(re.escape(struct.pack("<H", w)), d)]
            if offs:
                print(f"        {w:04X}: {', '.join(hex(o) for o in offs[:8])}")
    delta = calibrate_delta(d, tables)
    print(f"    VA->file delta: {delta:#x}")

    hot_found = False
    for t_off, run in tables:
        print(f"    suffix table @ file {t_off:#x}:")
        for suffix, p_params, p_alpha in run:
            if suffix == 0xFFFF:
                print("        FFFF  <end>")
                break
            tag = {0x9ABE: "  <<< NEW GENERATION", 0xAB9E: "  <<< (unconfirmed word)",
                   0xCF1B: "  <<< 8FC8 successor"}.get(suffix, "")
            if suffix in (0x9ABE, 0xAB9E, 0xCF1B):
                hot_found = True
            line = f"        {suffix:04X}"
            if p_params:
                po = (va2off(secs, p_params, d) if secs else p_params - delta)
                po = po if po is not None else -1
                line += f"  params VA={p_params:#x}"
                if 0 < po <= len(d) - 0x60:
                    line += f"\n            params[0:0x60] = {d[po:po+0x60].hex()}"
            else:
                line += "  params = NULL  -> derivation NOT local (EC / other path)"
            if p_alpha:
                ao = (va2off(secs, p_alpha, d) if secs else p_alpha - delta)
                ao = ao if ao is not None else -1
                if 0 < ao <= len(d) - 72:
                    alpha = d[ao:ao + 72].decode("latin1", "replace")
                    if alpha.isprintable():
                        line += f"\n            alphabet @ file {ao:#x} -> {alpha!r}"
            print(line + tag)
    if hot_found:
        print("\n    [**] NEW-GENERATION entry present with parameters -> local derivation;")
        print("         please report this whole output (and attach the module with --save).")
    if save_path:
        open(save_path, "wb").write(d)
        print(f"    [+] module bytes saved to {save_path}")


def process(name, data, out, depth):
    """Entry per blob: look for the vault module (PE with our strings)."""
    for m in re.finditer(re.escape(VAULT_FFS), data):
        print(f"[*] vault FFS GUID reference at {name}+{m.start():#x}")
    cands = []
    for m in re.finditer(rb"MZ", data):
        o = m.start()
        blob = data[o:o + 0x30000]
        if b"SecurityVault" in blob or ALPHA_PREFIX in blob:
            cands.append((o, blob))
    return cands


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--save", help="save found vault module bytes to this path")
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    print(f"[*] {args.file}: {len(data)} bytes")

    found = []
    # direct: PE blobs with vault content
    for o, blob in process("raw", data, None, 0):
        found.append((f"raw+{o:#x}", blob))
    # structured: FVs / FFS / LZMA sections
    out = []
    scan_blob(data, out, 0)
    for item in out:
        if item[0] == "file" and item[1] == VAULT_FFS.hex():
            print(f"[*] DellSecurityVaultSmm FFS file found ({len(item[3])} bytes)")
            # sections payload; find PE32 inside
            sub = []
            parse_sections(item[3], sub, 6)
            for s in sub:
                if s[0] == "pe32":
                    found.append(("FFS C7CAF1C7 PE32", s[1]))
            if not any(s[0] == "pe32" for s in sub):
                found.append(("FFS C7CAF1C7 raw", item[3]))
        elif item[0] == "lzma-section":
            print(f"[*] decompressed LZMA section: {len(item[1])} bytes")
        elif item[0] == "ui" and "vault" in str(item[1]).lower():
            print(f"[*] UI section: {item[1]!r}")
    # last resort: raw LZMA streams anywhere in the file
    if not found:
        print("[*] no FFS structure — trying raw LZMA stream scan ...")
        for off, blob in find_lzma_streams(data):
            print(f"[*] LZMA stream @{off:#x} -> {len(blob)} bytes")
            for o, b in process(f"lzma@{off:#x}", blob, None, 1):
                found.append((f"lzma@{off:#x}+{o:#x}", b))
            sub = []
            scan_blob(blob, sub, 1)
            for item in sub:
                if item[0] == "file" and item[1] == VAULT_FFS.hex():
                    pe = [s for s in [] ]
                    sub2 = []
                    parse_sections(item[3], sub2, 6)
                    for s in sub2:
                        if s[0] == "pe32":
                            found.append(("LZMA->FFS C7CAF1C7 PE32", s[1]))

    if not found:
        print("\n[-] no security-vault module found in this file.")
        print("    If this is a Dell BIOS update .exe, the payload may use a PFS container:")
        print("    run it through 'Dell PFS Extract' (Plato90s/BIOSUtilities) first, then retry")
        print("    on the extracted BIOS image (largest .bin / BIOS_IMG.rcv).")
        return 1
    for label, blob in found:
        report_module(blob, label, args.save)
    print("\nDone. Paste everything between the [*]/[+] lines when reporting back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
