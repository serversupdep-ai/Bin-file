#!/usr/bin/env python3
"""dell_newbios_probe.py — locate the unlock-suffix tables in ANY Dell firmware image.

Accepts: full SPI dump, BIOS region, BIOS_IMG.rcv recovery image, or (best effort)
a Dell BIOS .exe with an embedded uncompressed image. Extracts every FFS module via
uefi_firmware, finds the password-security modules (DellSecurityVaultSmm /
SystemPwSmm / HddPwSmm / DellNvmePwSmm / DellEcIoSmm), and reports:
  * new-gen suffix tables: 24-byte entries {u16 suffix; u32 pad; ptr params; ptr alpha}
    terminated by 0xFFFF  (params != NULL => derivation is LOCAL => keygen-able)
  * plain u16 suffix lists containing the queried words
  * 72-char scrambled alphabets in .data

Usage:  python3 dell_newbios_probe.py <image> [suffix-words like 9ABE,AB9E,8FCE,CF1B,8FC8]
"""
import os, re, struct, sys, tempfile, shutil

WANT = [0x9ABE, 0xAB9E, 0x8FCE, 0xCF1B, 0x8FC8, 0xE7A8]

SEC_MODULES = re.compile(r'(?i)(securityvault|systempw|hddpw|nvmePw|ecio|cipher|mfgauth)')

def parse_image(path):
    from uefi_firmware import AutoParser
    data = open(path, 'rb').read()
    p = AutoParser(data).parse()
    if p is not None:
        return data, p
    # carve: try each _FVH occurrence as a volume base inside a bare buffer
    for m in re.finditer(b'_FVH', data):
        off = m.start() - 0x28
        if off < 0:
            continue
        try:
            p = AutoParser(data[off:]).parse()
        except Exception:
            continue
        if p is not None:
            print(f"[i] carved firmware volume at file offset {off:#x}")
            return data[off:], p
    return data, None

def pe_sections(d):
    try:
        pe = struct.unpack('<I', d[0x3c:0x40])[0]
        optsz = struct.unpack('<H', d[pe+0x14:pe+0x16])[0]
        nsec = struct.unpack('<H', d[pe+6:pe+8])[0]
        off = pe + 0x18 + optsz
        secs = []
        for i in range(nsec):
            nm = d[off:off+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ra = struct.unpack('<IIII', d[off+8:off+24])
            secs.append((nm, va, vs, ra, rs))
            off += 40
        return secs
    except Exception:
        return []

def va2off(secs, va):
    for nm, v, vs, ra, rs in secs:
        if v <= va < v + vs and va - v < rs:
            return ra + (va - v)
    return None

def scan_module(name, d, want):
    secs = pe_sections(d)
    if not secs:
        return
    datava = None; datad = None
    for nm, v, vs, ra, rs in secs:
        if nm == '.data':
            datava, datad = v, d[ra:ra+rs]
    if datad is None:
        return
    found = []
    # 24-byte-entry table: u16 suffix, u16 pad, u32 pad, u64 params@+8, u64 alpha@+16
    for i in range(0, len(datad) - 48, 8):
        w0 = struct.unpack('<H', datad[i:i+2])[0]
        if w0 not in want:
            continue
        params, alpha = struct.unpack('<QQ', datad[i+8:i+24])
        term = struct.unpack('<H', datad[i+24:i+26])[0]
        # pointer-ish check: inside image, 8-aligned; alpha points at 72 printable-ish chars
        def off(p):
            o = va2off(secs, p)
            return o if o is not None and 0 <= o < len(d) else None
        ao = off(alpha); po = off(params)
        looks_alpha = ao is not None and sum(1 for c in d[ao:ao+72] if 32 <= c < 127) >= 70
        if (po is not None or params == 0) and looks_alpha:
            found.append((w0, params, alpha, d[ao:ao+72]))
    # plain u16 lists
    lists = []
    for i in range(0, len(datad) - 2, 2):
        w = struct.unpack('<H', datad[i:i+2])[0]
        if w in want:
            ctx = struct.unpack('<8H', datad[max(0,i-6):max(0,i-6)+16])
            known = {0xE7A8,0xBF97,0x6FF1,0x1F66,0x1D3B,0x2A7B,0x595B,0xD35B,0x1F5A,0x8FC8,0xFFFF,0x9ABE,0xAB9E,0x8FCE,0xCF1B}
            if sum(1 for u in ctx if u in known) >= 4:
                lists.append((i, [f"{u:04X}" for u in ctx]))
    if found or lists:
        print(f"\n=== {name}")
        for w0, params, alpha, alpha_bytes in found:
            print(f"  TABLE entry {w0:04X}: params={'NULL' if params==0 else hex(params)}  alpha={alpha:#x}")
            print(f"    alphabet: {alpha_bytes.decode('latin1')}")
        seen=set()
        for i, ws in lists:
            k=tuple(ws)
            if k in seen: continue
            seen.add(k)
            print(f"  LIST   @ .data+{i:#x}: {' '.join(ws)}")

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    path = sys.argv[1]
    want = [int(w, 16) for w in sys.argv[2].split(',')] if len(sys.argv) > 2 else WANT
    data, p = parse_image(path)
    if p is None:
        sys.exit("could not parse any firmware volume — if this is a Dell .exe, "
                 "extract BIOS_IMG.rcv / the payload first (or upload the .rcv)")
    tmp = tempfile.mkdtemp(prefix="probe_")
    try:
        p.dump(tmp)
    except Exception as e:
        sys.exit(f"dump failed: {e}")
    # find named modules
    mods = {}
    for root, _, files in os.walk(tmp):
        if 'section2.ui' in files:
            try:
                nm = open(os.path.join(root, 'section2.ui'), 'rb').read().decode('utf-16-le').rstrip('\0')
            except Exception:
                continue
            pe = os.path.join(root, 'section1.pe')
            if os.path.exists(pe) and SEC_MODULES.search(nm):
                mods[nm] = pe
    print(f"[i] security modules found: {sorted(mods)}")
    for nm, pe in sorted(mods.items()):
        scan_module(nm, open(pe, 'rb').read(), want)
    shutil.rmtree(tmp, ignore_errors=True)

if __name__ == '__main__':
    main()
