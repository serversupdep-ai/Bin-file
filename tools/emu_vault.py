#!/usr/bin/env python3
"""Unicorn-based emulator harness for DellSecurityVaultSmm (unlock-key derivation).

Loads the PE (uncompressed section1.pe from uefi_firmware extraction) at a fixed
base and calls internal derivation functions directly. No EFI runtime needed for
the self-contained paths (legacy MD5 families + E7A8 cipher core).
"""
import struct, sys
from unicorn import *
from unicorn.x86_const import *

VAULT = "/tmp/biosx/X/regions/region-bios/volume-0/file-1303221f-4197-b792-2466-f49e45233681/section0/section1/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-c7caf1c7-2d97-45cb-99d9-d89aaf8acc11/section1.pe"

BASE  = 0x00400000          # image base for emulation
STACK = 0x00700000          # stack region
STACK_SZ = 0x00100000
HEAP  = 0x00800000          # bump heap for pool allocs
HEAP_SZ = 0x00100000
SCRATCH = 0x00A00000        # arg buffers
SENTINEL = 0x0F000000       # fake return address

class Emu:
    def __init__(self, path=VAULT, verbose=False):
        self.d = bytearray(open(path, "rb").read())
        pe = struct.unpack('<I', self.d[0x3c:0x40])[0]
        self.optsz = struct.unpack('<H', self.d[pe+0x14:pe+0x16])[0]
        self.nsec  = struct.unpack('<H', self.d[pe+6:pe+8])[0]
        off = pe + 0x18 + self.optsz
        self.secs = []
        for i in range(self.nsec):
            nm = self.d[off:off+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ra = struct.unpack('<IIII', self.d[off+8:off+24])
            self.secs.append((nm, va, vs, ra, rs))
            off += 40
        self.imgsz = max(va+vs for _,va,vs,_,_ in self.secs)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc.mem_map(BASE, (self.imgsz + 0xFFF) & ~0xFFF)
        for nm, va, vs, ra, rs in self.secs:
            self.uc.mem_write(BASE+va, bytes(self.d[ra:ra+rs]))
        self._secs = self.secs
        # apply base relocations (preferred image base is 0 in these SMM PEs)
        reloc = [(n, v, s, r, rz) for (n, v, s, r, rz) in self.secs if n == '.reloc']
        for _, _, _, ra, rs in reloc:
            o, end = ra, ra+rs
            while o + 8 <= end:
                page, blk = struct.unpack('<II', self.d[o:o+8])
                if blk == 0: break
                for i in range((blk-8)//2):
                    e16 = struct.unpack('<H', self.d[o+8+2*i:o+10+2*i])[0]
                    if not e16: continue
                    typ, off = e16 >> 12, page + (e16 & 0xFFF)
                    fo = self._va2off(off)
                    if fo is None: continue
                    if typ == 0x0A:  # DIR64
                        old = struct.unpack('<Q', self.d[fo:fo+8])[0]
                        struct.pack_into('<Q', self.d, fo, old + BASE)
                    elif typ == 3:   # HIGHLOW
                        old = struct.unpack('<I', self.d[fo:fo+4])[0]
                        struct.pack_into('<I', self.d, fo, old + BASE)
                o += blk
        for nm, va, vs, ra, rs in self.secs:
            self.uc.mem_write(BASE+va, bytes(self.d[ra:ra+rs]))
        self.uc.mem_map(STACK, STACK_SZ)
        self.uc.mem_map(HEAP, HEAP_SZ)
        self.uc.mem_map(SCRATCH, 0x10000)
        self.uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
        self.heapptr = HEAP + 0x100
        self.verbose = verbose
        self.log = []
        # stub helpers installed on demand at STUB_BASE
        self.uc.mem_map(0x10000000, 0x1000)

    def _va2off(self, va):
        for nm, v, vs, ra, rs in self._secs:
            if v <= va < v+vs and va-v < rs:
                return ra + (va-v)
        return None

    def va(self, addr):  # emulation addr -> file offset
        r = addr - BASE
        for nm, va, vs, ra, rs in self.secs:
            if va <= r < va+vs and r-va < rs:
                return ra + (r-va)
        return None

    def call(self, fn, rcx=0, rdx=0, r8=0, r9=0, stackargs=(), rsp=STACK+STACK_SZ-0x2000, maxinstr=20_000_000):
        uc = self.uc
        rsp &= ~0xF
        # shadow + stack args (MS x64): [rsp+0x20] = arg5 ...
        for i, a in enumerate(stackargs):
            uc.mem_write(rsp+0x20+8*i, struct.pack('<Q', a))
        uc.mem_write(rsp-8, struct.pack('<Q', SENTINEL))
        uc.reg_write(UC_X86_REG_RSP, rsp-8)
        uc.reg_write(UC_X86_REG_RCX, rcx)
        uc.reg_write(UC_X86_REG_RDX, rdx)
        uc.reg_write(UC_X86_REG_R8, r8)
        uc.reg_write(UC_X86_REG_R9, r9)
        # volatile regs zero
        for r in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
                  UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15):
            uc.reg_write(r, 0)
        n = [0]
        def hook(uc, addr, size, ud):
            n[0] += 1
            if n[0] > maxinstr:
                uc.emu_stop()
                return
            if addr == SENTINEL:
                uc.emu_stop()
        h = uc.hook_add(UC_HOOK_CODE, hook)
        try:
            uc.emu_start(BASE+fn, SENTINEL, count=maxinstr)
        except UcError as e:
            rip = uc.reg_read(UC_X86_REG_RIP)
            raise RuntimeError(f"Unicorn error {e} at {rip:#x} (va {rip-BASE:#x} if in image) after {n[0]} instrs")
        finally:
            uc.hook_del(h)
        return uc.reg_read(UC_X86_REG_RAX)

if __name__ == '__main__':
    e = Emu()
    # sanity: call 0x5a60 sanitize directly: rcx=buf, rdx=7
    buf = SCRATCH
    e.uc.mem_write(buf, b'AB\x01CD\xFFZ')
    e.call(0x5a60, rcx=buf, rdx=7)
    out = e.uc.mem_read(buf, 7)
    print("sanitize:", bytes(out))
    assert bytes(out) == b'AB*CD*Z', "sanitize mismatch"
    print("harness OK")
