#!/usr/bin/env python3
"""dell_v2_keygen.py — E7A8-generation Dell BIOS unlock-key generator.

Runs the ACTUAL DellSecurityVaultSmm derivation from the firmware image in a
CPU emulator (Unicorn), so the output is by construction what the machine's
SMM code computes — no reimplementation drift.

RE background (see analysis/REPORT.md §6):
  DellSecurityVaultSmm contains, side by side:
    * legacy inline generator  == the public (bios-pw.org/dogber1) algorithm,
      canonicalised to the BF97 table — validated byte-exact vs our port;
    * new-generation generator: suffix table @0x9760 {u16 suffix; params; alpha}
      [0]=0x8FC8 (params NULL → handled by EC, see below),
      [1]=0xE7A8 (params @0x91e8, alphabet @0x9220),
      core cipher 0x46d8 + final map out[i]=alpha[(d[i]+d[i+16])%72].
  E7A8 entry point used here: fn B @0x58b4 (rcx=service tag, rdx=tag len,
  r8=out, r9=out len, stack+0x20=suffix word, stack+0x28=flag).

Validation (real-world, badcaps/iFixit reported WORKING codes, 2022..2025):
  65FDQN2-E7A8 -> zxdIkZ1XBrINbkDr      F2V9SQ2-E7A8 -> PIFQ2Nns9xMIIQsG
  D9B7JW2-E7A8 -> es6yZz5EaFBxE17Q      J4F3CV2-E7A8 -> d2bkF2QekQ2rbk9Q
  5LS8423-E7A8 -> RnGrGsQNZB1rIJ9r      G7LMQ73-E7A8 -> 1GIkGGGmZNc2RNMN
  6HDT5S2-E7A8 -> rhGyIG6Nk7MFE9Gk (code 2: Zq8r9P6rRGkMIhN1)

Also prints "Unlock Code 2" for E7A8 via tools/dell_e7a8_pure.py — a pure-python
port of the validated "Second" encoder (extended const table + inner depth 16),
14/14 vectors. That engine doubles as a zero-dependency fallback: without
unicorn installed, this script still generates both E7A8 codes.

IMPORTANT — suffix generations (verified against forums + this firmware, BIOS 1.13.0):
  legacy 2A7B/1D3B/1F66/6FF1/1F5A/BF97/595B/D35B (+HDD) -> public algo, dell_master_keygen.py
  E7A8 (2018-2024 BIOS)  -> THIS tool (7/7 real-world vectors). Dell ROTATED the E7A8
         params in late-2024 BIOS builds: machines with those BIOSes (e.g. FFC06D3,
         89J3S73 Latitude 3190, Oct-2024+) need the params from THEIR BIOS image
         (run tools/dell_newbios_probe.py on it, then this tool with --pe).
  0001 (2024+)           -> emulation shows the SMM code falls back to the legacy
         canonical (BF97-table) key; community reports the master-password option is
         DISABLED in this state, so codes are usually rejected -> dump-patch instead.
  8FC8 (2020-2025)       -> derivation done inside the Embedded Controller (mailbox
         via DellEcIoSmm); no local keygen possible from the BIOS image alone.
  CF1B (2025+)           -> 8FC8's successor per community; same expected architecture.
  9ABE (2025-2026)       -> newest generation; not present in BIOS 1.13.0 - requires
         the newer BIOS image (upload BIOS_IMG.rcv from the machine's driver page).
  3FE2 (2021+)           -> "BIOS Service Tag Lockout" state, treated like 8FC8
         cases (dump patch); no key-based unlock.
  "8FCE"                 -> no such suffix exists in any forum report; OCR/typo of 8FC8.

8FC8 (Precision 3581 & other 2024+ models): the BIOS deliberately does NOT
contain the derivation — fn B returns EFI_INVALID_PARAMETER for suffix 8FC8 and
the vault module instead sends (input, fixed 16-byte command, suffix) to the
Embedded Controller via DellEcIoSmm port I/O and reads back the 32 bytes it
maps through the 8FC8 alphabet. A local keygen for 8FC8 therefore requires the
EC firmware (separate chip, not part of the BIOS dump). Use
tools/dell_8fc8_patch.py to unlock deterministically from a dump instead.

Usage:
  python3 dell_v2_keygen.py --tag 65FDQN2 --suffix E7A8 \
         [--pe /path/to/DellSecurityVaultSmm.section1.pe | --dump /path/to/32MB.bin]
  python3 dell_v2_keygen.py --self-test

Requires: pip install unicorn   (and uefi_firmware only when using --dump)
"""
import argparse, os, re, struct, sys, tempfile, shutil

# --------------------------------------------------------------------------- #
# harness (same as tools/emu_vault.py, kept self-contained for portability)
# --------------------------------------------------------------------------- #
try:
    from unicorn import *
    from unicorn.x86_const import *
    HAVE_UNICORN = True
except ImportError:            # pure-python fallback still covers E7A8 (both codes)
    HAVE_UNICORN = False

BASE     = 0x00400000
STACK    = 0x00700000
STACK_SZ = 0x00100000
SCRATCH  = 0x00A00000
SENTINEL = 0x0F000000

VAULT_FFS_GUID_DIR = "file-c7caf1c7-2d97-45cb-99d9-d89aaf8acc11"

# fn B (generate) prologue signature — DellSecurityVaultSmm, Precision 3581 BIOS
SIG_FNB = bytes.fromhex("48895c240848896c24104889742418574883ec60488be90fb78c2490000000")
# classify(suffixWord) signature: xor edx,edx; mov eax,0x8fc8; cmp ax,cx; je +0x25
SIG_CLASSIFY = bytes.fromhex("33d2b8c88f0000663bc17425")

E7A8_ALPHABET_PREFIX = b"Q92G0drk9y63r5DG1hLqJGW1EnRk"
FC8_ALPHABET_PREFIX  = b"0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZ"

class VaultEmu:
    def __init__(self, pe_bytes):
        d = bytearray(pe_bytes)
        pe = struct.unpack('<I', d[0x3c:0x40])[0]
        optsz = struct.unpack('<H', d[pe+0x14:pe+0x16])[0]
        off = pe + 0x18 + optsz
        secs = []
        for i in range(struct.unpack('<H', d[pe+6:pe+8])[0]):
            nm = d[off:off+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ra = struct.unpack('<IIII', d[off+8:off+24])
            secs.append((nm, va, vs, ra, rs))
            off += 40
        imgsz = max(va+vs for _, va, vs, _, _ in secs)
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(BASE, (imgsz + 0xFFF) & ~0xFFF)
        uc.mem_map(STACK, STACK_SZ)
        uc.mem_map(SCRATCH, 0x10000)
        uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
        # apply base relocations (preferred image base is 0)
        def va2off(va):
            for nm, v, vs, ra, rs in secs:
                if v <= va < v+vs and va-v < rs:
                    return ra + (va-v)
            return None
        for nm, va, vs, ra, rs in secs:
            if nm != '.reloc':
                continue
            o, end = ra, ra+rs
            while o + 8 <= end:
                page, blk = struct.unpack('<II', d[o:o+8])
                if blk == 0:
                    break
                for i in range((blk-8)//2):
                    e16 = struct.unpack('<H', d[o+8+2*i:o+10+2*i])[0]
                    if not e16:
                        continue
                    typ, tva = e16 >> 12, page + (e16 & 0xFFF)
                    fo = va2off(tva)
                    if fo is None:
                        continue
                    if typ == 0x0A:
                        old = struct.unpack('<Q', d[fo:fo+8])[0]
                        struct.pack_into('<Q', d, fo, old + BASE)
                    elif typ == 3:
                        old = struct.unpack('<I', d[fo:fo+4])[0]
                        struct.pack_into('<I', d, fo, old + BASE)
                o += blk
        for nm, va, vs, ra, rs in secs:
            uc.mem_write(BASE+va, bytes(d[ra:ra+rs]))
        self.uc, self.secs, self.d = uc, secs, d
        self.heapptr = SCRATCH + 0x2000

    def text(self):
        for nm, va, vs, ra, rs in self.secs:
            if nm == '.text':
                return bytes(self.d[ra:ra+rs]), va
        return b'', 0

    def call(self, fn, rcx=0, rdx=0, r8=0, r9=0, stackargs=(), rsp=STACK+STACK_SZ-0x4000):
        uc = self.uc
        rsp &= ~0xF
        for i, a in enumerate(stackargs):
            uc.mem_write(rsp+0x20+8*i, struct.pack('<Q', a))
        uc.mem_write(rsp-8, struct.pack('<Q', SENTINEL))
        uc.reg_write(UC_X86_REG_RSP, rsp-8)
        uc.reg_write(UC_X86_REG_RCX, rcx)
        uc.reg_write(UC_X86_REG_RDX, rdx)
        uc.reg_write(UC_X86_REG_R8, r8)
        uc.reg_write(UC_X86_REG_R9, r9)
        for r in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                  UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15):
            uc.reg_write(r, 0)
        hit = [0]
        def hook(uc_, addr, size, ud):
            hit[0] += 1
            if addr == SENTINEL or hit[0] > 20_000_000:
                uc_.emu_stop()
        h = uc.hook_add(UC_HOOK_CODE, hook)
        try:
            uc.emu_start(BASE+fn, SENTINEL, count=20_000_000)
        except UcError as e:
            raise RuntimeError(f"emulation failed: {e} at va {uc.reg_read(UC_X86_REG_RIP)-BASE:#x}")
        finally:
            uc.hook_del(h)
        return uc.reg_read(UC_X86_REG_RAX)

# --------------------------------------------------------------------------- #
# firmware acquisition
# --------------------------------------------------------------------------- #
def pe_from_dump(dump_path):
    """Extract DellSecurityVaultSmm section1.pe from a full SPI dump via uefi_firmware."""
    try:
        from uefi_firmware import AutoParser
    except ImportError:
        sys.exit("--dump requires 'uefi_firmware' (pip install uefi_firmware); "
                 "or pass --pe with the already-extracted module")
    data = open(dump_path, 'rb').read()
    tmp = tempfile.mkdtemp(prefix="dellv2_")
    try:
        AutoParser(data).parse().showinfo()  # noqa: F841 (progress noise ok)
    except Exception:
        pass
    # full dump then find by FFS GUID folder
    try:
        AutoParser(data).parse().dump(tmp)
    except Exception as e:
        sys.exit(f"uefi_firmware dump failed: {e}")
    for root, _, files in os.walk(tmp):
        if os.path.basename(root).startswith(VAULT_FFS_GUID_DIR[:20]):
            for fn in files:
                if fn.endswith('.pe') and 'section1' in fn:
                    p = os.path.join(root, fn)
                    b = open(p, 'rb').read()
                    shutil.rmtree(tmp, ignore_errors=True)
                    return b
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit("DellSecurityVaultSmm (FFS c7caf1c7-2d97-45cb-99d9-d89aaf8acc11) not found in dump")

def locate_fn_b(pe_bytes):
    """Find the generator entry by signature; fall back to the reference offset."""
    e = VaultEmu(pe_bytes)  # relocation pass runs on a throwaway copy
    d = bytes(e.d)
    text, tva = e.text()
    off = text.find(SIG_FNB)
    if off >= 0:
        return e, tva + off
    if d.find(SIG_CLASSIFY) >= 0 and b"E7A8" not in d:
        pass
    if b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57" in text:
        # signature body differs (different BIOS build): try reference offset if module matches
        if E7A8_ALPHABET_PREFIX in d and FC8_ALPHABET_PREFIX in d:
            return e, 0x58b4  # reference build (Precision 3581, 2025)
    sys.exit("could not locate the generator function — unexpected module build; "
             "use --pe with the DellSecurityVaultSmm from this machine's BIOS")

# --------------------------------------------------------------------------- #
# key generation
# --------------------------------------------------------------------------- #
SUFFIX_WORDS = {
    'E7A8': 0xE7A8, '8FC8': 0x8FC8, '0001': 0x0001, '3FE2': 0x3FE2, '9ABE': 0x9ABE,
    'AB9E': 0xAB9E, '8FCE': 0x8FCE, 'CF1B': 0xCF1B,
    '2A7B': 0x2A7B, '1D3B': 0x1D3B, '1F66': 0x1F66, '6FF1': 0x6FF1, 'BF97': 0xBF97,
    '1F5A': 0x1F5A, '595B': 0x595B, 'D35B': 0xD35B, 'A95B': 0xA95B,
}

def generate(emu, fn_b, tag: str, suffix_word: int, out_len=16, in_len=None):
    if in_len is None:
        in_len = len(tag)
    tag_b = tag.encode('latin1', 'replace')[:20]
    IN  = SCRATCH
    OUT = SCRATCH + 0x100
    emu.uc.mem_write(IN, tag_b.ljust(32, b'\0'))
    emu.uc.mem_write(OUT, b'\0'*64)
    rv = emu.call(fn_b, rcx=IN, rdx=in_len, r8=OUT, r9=out_len,
                  stackargs=(suffix_word, 1))
    out = bytes(emu.uc.mem_read(OUT, out_len))
    return rv, out

VECTORS = [
    ("65FDQN2", 0xE7A8, "zxdIkZ1XBrINbkDr"),
    ("D9B7JW2", 0xE7A8, "es6yZz5EaFBxE17Q"),
    ("5LS8423", 0xE7A8, "RnGrGsQNZB1rIJ9r"),
    ("F2V9SQ2", 0xE7A8, "PIFQ2Nns9xMIIQsG"),
    ("J4F3CV2", 0xE7A8, "d2bkF2QekQ2rbk9Q"),
    ("G7LMQ73", 0xE7A8, "1GIkGGGmZNc2RNMN"),
    ("6HDT5S2", 0xE7A8, "rhGyIG6Nk7MFE9Gk"),
    ("DELLSUX", 0xBF97, "rrNM2LrbD8nGsd2P"),  # legacy canonical == public v1
]

def self_test(emu, fn_b):
    ok = 0
    for tag, sfx, exp in VECTORS:
        rv, out = generate(emu, fn_b, tag, sfx)
        got = out.decode('latin1')
        good = got == exp
        ok += good
        print(f"  {'PASS' if good else 'FAIL'}  {tag}-{sfx:04X}: {got} (expected {exp})")
    print(f"{ok}/{len(VECTORS)} vectors passed")
    return ok == len(VECTORS)

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--tag', help='7-character Dell service tag (e.g. 65FDQN2)')
    ap.add_argument('--suffix', default='E7A8', help='suffix family: E7A8 (validated) or legacy word')
    ap.add_argument('--pe', help='path to extracted DellSecurityVaultSmm section1.pe')
    ap.add_argument('--dump', help='path to full SPI dump (needs uefi_firmware)')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args()

    pe = None
    if not HAVE_UNICORN:
        # No emulator: pure-python E7A8 engine (validated 14/14, both codes).
        sfx = (args.suffix or 'E7A8').strip().upper()
        if args.tag and sfx == 'E7A8':
            import dell_e7a8_pure
            tag = args.tag.strip().upper()
            c1, c2 = dell_e7a8_pure.generate(tag)
            print(f"Dell {tag}-E7A8   [unicorn not installed -> pure-python engine]")
            print(f"  unlock code: {c1}")
            print(f"  code 2     : {c2}")
            print("Notes: US QWERTY; hold Ctrl then press Enter twice (Ctrl-Enter-Enter).")
            sys.exit(0)
        sys.exit("unicorn is not installed (pip install unicorn); without it only E7A8 "
                 "is supported via the pure-python engine")
    if args.pe:
        pe = open(args.pe, 'rb').read()
    elif args.dump:
        pe = pe_from_dump(args.dump)
    else:
        # bundled module (Precision 3581 BIOS 1.13.0) -> session scratch copy
        bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "firmware", "DellSecurityVaultSmm_3581_BIOS1.13.0.pe")
        cand = ("/tmp/biosx/X/regions/region-bios/volume-0/file-1303221f-4197-b792-2466-f49e45233681"
                "/section0/section1/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/"
                "file-c7caf1c7-2d97-45cb-99d9-d89aaf8acc11/section1.pe")
        for c in (bundled, cand):
            if os.path.exists(c):
                pe = open(c, 'rb').read()
                break
        if pe is None:
            sys.exit("no firmware source: pass --pe or --dump (see --help)")
    emu, fn_b = locate_fn_b(pe)

    if args.self_test:
        sys.exit(0 if self_test(emu, fn_b) else 1)

    if not args.tag:
        ap.error('--tag is required (or use --self-test)')
    tag = args.tag.strip().upper()
    sfx = args.suffix.strip().upper()
    word = SUFFIX_WORDS.get(sfx)
    if word is None and re.fullmatch(r'[0-9A-F]{4}', sfx):
        word = int(sfx, 16)
    if word is None:
        sys.exit(f"unknown suffix {sfx!r}; use E7A8 or a 4-hex-digit family word")

    if word == 0x8FC8 or word == 0x8FCE:
        print("8FC8: this BIOS generation performs the derivation inside the Embedded\n"
              "Controller (DellEcIoSmm mailbox), not in SMM — no local keygen exists.\n"
              "('8FCE' is not a real suffix — it is a typo/OCR of 8FC8.)\n"
              "Unlock deterministically from a dump instead: tools/dell_8fc8_patch.py")
        sys.exit(2)
    if word in (0x9ABE, 0xAB9E, 0xCF1B):
        print(f"{sfx}: newest generation — NOT present in BIOS 1.13.0 (this firmware only\n"
              "has 8FC8/E7A8). Get BIOS_IMG.rcv from the machine's Dell driver page and run\n"
              "tools/dell_newbios_probe.py on it; if the new table entry has params != NULL,\n"
              "this same emulator approach yields a keygen immediately.")
        sys.exit(2)
    if word in (0x0001, 0x3FE2):
        print(f"{sfx}: per forum research this state indicates the master-password option\n"
              "is disabled (0001) or a Service-Tag lockout (3FE2); emulation shows 0001 falls\n"
              "back to the legacy canonical key, which machines in this state usually reject.\n"
              "Recommended: dump patch (tools/dell_8fc8_patch.py). Showing the fallback anyway.")

    rv, out = generate(emu, fn_b, tag, word)
    if rv & 0xFFFFFFFF00000000 and (rv >> 32) == 0x80000000:
        sys.exit(f"firmware rejected the request (status {rv:#x})")
    print(f"Dell {tag}-{sfx}")
    print(f"  unlock code: {out.decode('latin1')}")
    if word == 0xE7A8:
        try:
            import dell_e7a8_pure
            c1, c2 = dell_e7a8_pure.generate(tag)
            print(f"  code 2     : {c2}   (pure-python engine; try if code 1 is rejected)")
        except Exception as e:
            print(f"  (code 2 unavailable: {e})")
    print("Notes: US QWERTY; hold Ctrl then press Enter twice (Ctrl-Enter-Enter).")
    print("      For legacy families also try the 1F5A/BF97 code (tools/dell_master_keygen.py).")

if __name__ == '__main__':
    main()
