#!/usr/bin/env python3
"""dell_param_solver.py — structured search for E7A8-family parameter blocks.

"Play with the keys": Dell's unlock-suffix encoders (legacy 595B-family and
new-gen E7A8) all share one skeleton:

    loopParams   = [p0, p1, p2, p3]            # small ints (17,13,12,8 public)
    encodeParams = [A,B,C,D, D,E,F,A]          # ep[0]==ep[7], ep[3]==ep[4]
    final map    = alphabet[(sha256(state)[i]+sha256(state)[i+16]) % 72]

Legacy suffixes differ from the base by TINY deltas (1D3B: ^0x50501010+j,
6FF1: |0x50501010-j, ...) — evidence that per-generation "rotation" moves
constants only slightly around the template. This tool searches that
structured space against a known (tag -> code) oracle, so a parameter block
can be recovered WITHOUT the firmware image when a single real code pair is
known (worked example: late-2024 BIOS branches).

Usage:
    python3 dell_param_solver.py --tag FFC06D3 --code1 ZzIL1LJL3260RGdI \
        [--code2 2Wrrzc6Nq2DG0QQZ] [--suffix E7A8] [--stages quick,a,b]
"""

import argparse
import itertools
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from dell_e7a8_pure import (ALPHABET, E7A8Encoder, E7A8EncoderSecond,
                            _finish, tag_to_block)

BASE_LP = [17, 13, 12, 8]
BASE_EP = [0x50501010, 0x0A010908, 0x00A08097, 0x60606161,
           0x60606161, 0x000A0008, 0x00100097, 0x50501010]
XOR_MAGIC = 0x6D2F93A5          # public code-2 table-extension constant


def make_encoder(lp, ep, second=False):
    class E(E7A8EncoderSecond if second else E7A8Encoder):
        pass
    E.loop_params = list(lp)
    E.encode_params = list(ep)
    return E


def code_for(lp, ep, block, second=False):
    try:
        return _finish(make_encoder(lp, ep, second).encode(block))
    except IndexError:
        return None          # inner depth exceeds constant-table length


def bswap(x):
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24)


# ---------------------------------------------------------------- stages --

def stage_quick(block, t1, t2=None):
    """Structural transforms of the public block (XOR magic, swaps, ...)."""
    lps = [BASE_LP,
           [13, 17, 8, 12], [17, 13, 12, 16],          # Second's depth
           [17, 13, 16, 8], [13, 13, 12, 8], [21, 13, 12, 8],
           [17, 9, 12, 8], [17, 17, 12, 8], [25, 13, 12, 8]]
    eps = [BASE_EP,
           [x ^ XOR_MAGIC for x in BASE_EP],            # whole-block XOR
           [bswap(x) for x in BASE_EP],                 # byte-swapped
           BASE_EP[::-1],                               # reversed
           [BASE_EP[0], BASE_EP[5], BASE_EP[6], BASE_EP[3],
            BASE_EP[4], BASE_EP[1], BASE_EP[2], BASE_EP[7]],  # pairs swap
           [BASE_EP[3], BASE_EP[2], BASE_EP[1], BASE_EP[0],
            BASE_EP[7], BASE_EP[6], BASE_EP[5], BASE_EP[4]],  # half-reverse
           ]
    hits = []
    for lp in lps:
        for ep in eps:
            for second in (False, True):
                c1 = code_for(lp, ep, block, second)
                if c1 == t1:
                    hits.append((lp, ep, second, c1))
    return hits


def stage_lp(block, t1):
    """loopParams-only search, encodeParams fixed."""
    r0 = [9, 13, 17, 21, 25]
    r1 = [9, 13, 17, 21]
    r2 = [8, 12, 16, 20]
    r3 = [4, 8, 12, 16, 20]
    hits = []
    for lp in itertools.product(r0, r1, r2, r3):
        for second in (False, True):
            if code_for(list(lp), BASE_EP, block, second) == t1:
                hits.append((list(lp), BASE_EP, second))
    return hits


def stage_ep(block, t1, window=None):
    """encodeParams deltas around template (structure ep[0]==ep[7], ep[3]==ep[4])."""
    if window is None:
        d = [0, 1, -1, 8, -8, 0x10, -0x10, 0x100, -0x100, 0x1000, -0x1000]
        window = [BASE_EP[1] + x for x in d] and None
    # distinct knobs: a=ep[0]=ep[7], b=ep[1], c=ep[2], dd=ep[3]=ep[4],
    #                 e=ep[5], f=ep[6]
    def near(v):
        return sorted({v, v ^ 1, v + 1, v - 1, v + 8, v - 8,
                       v ^ 0x10, v + 0x10, v - 0x10, v ^ 0x100,
                       v + 0x100, v - 0x100, v ^ 0x1000, v + 0x1000,
                       v - 0x1000, v & 0xFFFFFFFF})
    A = near(BASE_EP[0])[:9]
    B = near(BASE_EP[1])
    C = near(BASE_EP[2])
    D = near(BASE_EP[3])[:9]
    E = near(BASE_EP[5])
    F = near(BASE_EP[6])
    hits = []
    t0 = time.time()
    n = 0
    for a in A:
        for b in B:
            for c in C:
                for dd in D:
                    ep = [a, b, c, dd, dd, BASE_EP[5], BASE_EP[6], a]
                    n += 1
                    if code_for(BASE_LP, ep, block) == t1:
                        hits.append((BASE_LP, ep, False))
                if time.time() - t0 > 240:
                    print(f"    [stage b] timeout after {n} combos")
                    return hits
    print(f"    [stage b] scanned {n} combos (a,b,c,d knobs)")
    # e/f knobs on top of best-null: full pass with e,f varied (bounded)
    for a in A[:5]:
        for b in B[:8]:
            for e in E[:8]:
                for f in F[:8]:
                    ep = [a, b, BASE_EP[2], BASE_EP[3], BASE_EP[3], e, f, a]
                    n += 1
                    if code_for(BASE_LP, ep, block) == t1:
                        hits.append((BASE_LP, ep, False))
                if time.time() - t0 > 480:
                    print(f"    [stage b2] timeout at {n}")
                    return hits
    return hits


STAGES = {"quick": stage_quick, "a": stage_lp, "b": stage_ep}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--code1", required=True)
    ap.add_argument("--code2")
    ap.add_argument("--suffix", default="E7A8")
    ap.add_argument("--stages", default="quick,a,b")
    args = ap.parse_args()

    block = tag_to_block(args.tag.upper())
    # replace suffix inside the block if not E7A8
    if args.suffix.upper() != "E7A8":
        data = (args.tag.upper() + args.suffix.upper()).encode()
        block = []
        for i in range(16):
            c = data[i * 4:i * 4 + 4]
            v = 0
            for k, ch in enumerate(c):
                v |= ch << (8 * k)
            block.append(v)

    print(f"[*] oracle: {args.tag}-{args.suffix} -> {args.code1}"
          + (f" / {args.code2}" if args.code2 else ""))
    all_hits = []
    for name in args.stages.split(","):
        fn = STAGES[name.strip()]
        print(f"[*] stage {name} ...")
        hits = fn(block, args.code1, args.code2) if name == "quick" else fn(block, args.code1)
        for h in hits:
            lp, ep, second = h[0], h[1], h[2]
            k2 = code_for(lp, ep, block, True)
            print(f"[+] HIT: lp={lp} ep={[hex(x) for x in ep]} second={second}")
            print(f"    code1={args.code1} code2_check={k2}"
                  + ("  <-- MATCHES ORACLE CODE2" if args.code2 and k2 == args.code2 else ""))
            all_hits.append(h)
    if not all_hits:
        print("[-] no hit in structured space — rotation is farther from template")
    return 0 if all_hits else 1


if __name__ == "__main__":
    sys.exit(main())
