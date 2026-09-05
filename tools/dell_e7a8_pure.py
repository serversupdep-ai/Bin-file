#!/usr/bin/env python3
"""dell_e7a8_pure.py — pure-Python E7A8-generation Dell BIOS unlock-key engine.

Produces BOTH unlock codes ("Unlock Code 1" and "Unlock Code 2") for Dell
machines showing the -E7A8 suffix, WITHOUT needing the firmware module or
the Unicorn emulator. This is the validated algorithm (structure: MD5-like
rounds with custom tables — "E7A8" family), ported from the public engine
(chromebreakerdev/Dell-Unlocker WORKINGKEYGEN.py) and cross-validated:

  * code 1 == firmware emulation (DellSecurityVaultSmm fn @0x58b4) on 7/7
    real-world vectors,
  * code 2 == the "Second" encoder; witnessed in public on 6HDT5S2
    (badcaps thread, Zq8r9P6rRGkMIhN1).

SCOPE: works for BIOS builds that carry the pre-rotation E7A8 parameters
(observed on 1.13.0-era firmware, 2018..mid-2024). Dell rotated the tables
in late-2024 BIOS builds — for those, use dell_v2_keygen.py --dump with the
machine's own BIOS image.

Usage:
    python3 dell_e7a8_pure.py 65FDQN2
    python3 dell_e7a8_pure.py --selftest
"""

import hashlib
import sys

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _m32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rol(x: int, b: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << b) & 0xFFFFFFFF) | (x >> (32 - b))


# MD5 round rotation amounts (standard)
_ROT = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
]

# Modified MD5 constant table ("md5magic2"): standard MD5 K table with the
# second half replaced by earlier values (the E7A8 tweak).
MD5TABLE2 = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
]

# Output alphabet (65 chars, firmware copy at module offset 0x9220 region).
ALPHABET = "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"

# --------------------------------------------------------------------------
# round functions (MD5 F/G/H/I analogues, E7A8 variants — all 32-bit)
#   f1(t, c)   = t - c
#   f2(b,c,d)  = (~d ^ c) & b      ^ ~d
#   f3(b,c,d)  = ((b ^ c) & d) ^ c
#   f4(b,c,d)  = (~c ^ b) ^ d
#   f5(b,c,d)  = (~b | ~d) ^ c
# --------------------------------------------------------------------------

def _f1(t: int, c: int) -> int:
    return (t - c) & 0xFFFFFFFF


def _f2(b: int, c: int, d: int) -> int:
    nd = ~d & 0xFFFFFFFF
    return ((nd ^ c) & b) ^ nd


def _f3(b: int, c: int, d: int) -> int:
    return ((b ^ c) & d) ^ c


def _f4(b: int, c: int, d: int) -> int:
    return ((~c & 0xFFFFFFFF) ^ b) ^ d


def _f5(b: int, c: int, d: int) -> int:
    return (((~b & 0xFFFFFFFF) | (~d & 0xFFFFFFFF)) & 0xFFFFFFFF) ^ c


# --------------------------------------------------------------------------
# encoder core
# --------------------------------------------------------------------------

class E7A8Encoder:
    """Code-1 encoder ("first")."""

    loop_params = [17, 13, 12, 8]
    encode_params = [
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008, 0x100097, 0x50501010,
    ]

    def __init__(self, block):
        self.md5table = MD5TABLE2
        self.block = block            # 16 little-endian words (service tag + "E7A8", zero-padded)
        self.state = [0, 0, 0, 0]     # A, B, C, D
        self.A = self.B = self.C = self.D = 0

    # -- round step ----------------------------------------------------
    def _calculate(self, fun, key1: int, key2: int) -> int:
        tmp = fun(self.B, self.C, self.D)
        combined = (self.md5table[key2] + self.block[key1 & 7]) & 0xFFFFFFFF
        return (self.A + _f1(tmp, combined)) & 0xFFFFFFFF

    def _shortcut(self, fun, j, md5_index, rot_index, indexes):
        for i in range(4):
            t = self._calculate(fun, (j + indexes[i]) & 7, md5_index + i)
            old_b = self.B
            self.A = self.D
            self.D = self.C
            self.C = old_b
            self.B = _m32(old_b + _rol(t, _ROT[rot_index][i]))

    def _increment(self):
        for i, v in enumerate((self.A, self.B, self.C, self.D)):
            self.state[i] = _m32(self.state[i] + v)

    # -- main loop -----------------------------------------------------
    def make_encode(self):
        lp, ep = self.loop_params, self.encode_params
        # first big loop: p in [0, lp[0])
        for p in range(lp[0]):
            self.A |= ep[0]
            self.B ^= ep[1]
            self.C |= (ep[2] - p) & 0xFFFFFFFF
            self.D ^= (ep[3] + p) & 0xFFFFFFFF
            for j in range(0, lp[2], 4):
                self._shortcut(_f2, j, j + 32, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self._shortcut(_f3, j, j, 1, [1, -2, -1, 0])
            for j in range(lp[3], 3, -4):
                self._shortcut(_f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(lp[3], 3, -4):
                self._shortcut(_f5, j, j + 48, 3, [2, 3, 2, -3])
            self._increment()
        # second loop: p in [0, lp[1])
        for p in range(lp[1]):
            self.A |= ep[4]
            self.B ^= ep[5]
            self.C |= (ep[6] - p) & 0xFFFFFFFF
            self.D ^= (ep[7] + p) & 0xFFFFFFFF
            for j in range(lp[3], 3, -4):
                self._shortcut(_f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(0, lp[2], 4):
                self._shortcut(_f5, j, j + 32, 3, [2, 3, 2, -3])
            for j in range(lp[3], 0, -4):
                self._shortcut(_f2, j, j, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self._shortcut(_f3, j, j + 48, 1, [1, -2, 3, 0])
            self._increment()

    @classmethod
    def encode(cls, block):
        obj = cls(block)
        obj.make_encode()
        return list(obj.state)


class E7A8EncoderSecond(E7A8Encoder):
    """Code-2 encoder: extended constant table + inner-loop depth 16."""

    def __init__(self, block):
        super().__init__(block)
        overfill = [0xA0008 ^ 0x6D2F93A5, 0xA08097 ^ 0x6D2F93A5,
                    0xA010908 ^ 0x6D2F93A5, 0x60606161 ^ 0x6D2F93A5]
        self.md5table = MD5TABLE2 + overfill
        self.loop_params = [17, 13, 12, 16]


# --------------------------------------------------------------------------
# input block + final mapping
# --------------------------------------------------------------------------

def tag_to_block(tag: str):
    """service tag + 'E7A8' -> 16 LE 32-bit words."""
    data = (tag.upper() + "E7A8").encode("ascii")
    block = []
    for i in range(16):
        chunk = data[i * 4:i * 4 + 4]
        v = 0
        for k, b in enumerate(chunk):
            v |= b << (8 * k)
        block.append(v)
    return block


def _finish(encoded_state):
    raw = b"".join(v.to_bytes(4, "little") for v in encoded_state)
    digest = hashlib.sha256(raw).digest()
    out = []
    for i in range(16):
        idx = (digest[i + 16] + digest[i]) % len(ALPHABET)
        out.append(ALPHABET[idx])
    return "".join(out)


def generate(tag: str):
    """Return (code1, code2) for a 7-char Dell service tag."""
    block = tag_to_block(tag.strip().upper())
    code1 = _finish(E7A8Encoder.encode(block))
    code2 = _finish(E7A8EncoderSecond.encode(block))
    return code1, code2


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

# Real-world vectors: code 1 confirmed on 7/7 (forums + firmware emulation);
# code 2 confirmed publicly for 6HDT5S2 (badcaps), algorithm-validated for
# the rest against the public engine.
# Generator-confirmed (every code pair ever publicly generated matches this
# engine exactly): 1JGPCK2 (Reddit iks99h), 5957FH2 (codes REJECTED by the
# machine -> its BIOS uses rotated params), BXBGRQ2 Latitude 7490 (iks99h).
VECTORS = [
    ("65FDQN2", "zxdIkZ1XBrINbkDr", "a0ycrkLr9Be8BZze"),
    ("D9B7JW2", "es6yZz5EaFBxE17Q", "GrIUZsQ3ex529M[6"),
    ("5LS8423", "RnGrGsQNZB1rIJ9r", "QazRb9ayEDQ6913P"),
    ("F2V9SQ2", "PIFQ2Nns9xMIIQsG", "rGBy3x[n12Ekr[3e"),
    ("J4F3CV2", "d2bkF2QekQ2rbk9Q", "nrjy23QrF6dMqL1I"),
    ("G7LMQ73", "1GIkGGGmZNc2RNMN", "QrzQkJ7ZGRRWXEUQ"),
    ("6HDT5S2", "rhGyIG6Nk7MFE9Gk", "Zq8r9P6rRGkMIhN1"),  # both publicly witnessed
    ("1JGPCK2", "67M[kP4k92yG4nMQ", "RGRb5UBrrEa8hrGL"),  # reddit generator-confirmed
    ("BXBGRQ2", "9yZ19ZRG0nZkDkGx", "ZIGc2UMjZD[ZcypI"),  # Latitude 7490, generator-confirmed
    ("5957FH2", "XPN[Z7MeDqa[3D4I", "Ra72s2N92ZFUR3Ek"),  # generator-confirmed; machine REJECTED (rotated params)
]


def self_test():
    ok = 0
    for tag, k1, k2 in VECTORS:
        c1, c2 = generate(tag)
        m1 = "OK " if c1 == k1 else "FAIL"
        m2 = "OK " if c2 == k2 else "FAIL"
        print(f"  {m1} {m2}  {tag}-E7A8  code1={c1}  code2={c2}")
        ok += (c1 == k1) + (c2 == k2)
    print(f"{ok}/{2 * len(VECTORS)} vectors pass")
    return ok == 2 * len(VECTORS)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        sys.exit(0 if self_test() else 1)
    if len(sys.argv) != 2 or not (6 <= len(sys.argv[1]) <= 7):
        print(__doc__)
        sys.exit(2)
    tag = sys.argv[1].upper()
    c1, c2 = generate(tag)
    print(f"{tag}-E7A8  Unlock Code 1: {c1}")
    print(f"{tag}-E7A8  Unlock Code 2: {c2}")


if __name__ == "__main__":
    main()
