#!/usr/bin/env python3
"""
Rigorous arithmetic fingerprint analysis of IMEI -> unlock-code pairs.
"""

# Given pairs
pairs = {
    "Pair 1": {
        "imei_str": "350932556677169",
        "code_str": "3179082691806135",
    },
    "Pair 2": {
        "imei_str": "353138606737097",
        "code_str": "2635791635092793",
    },
}

# Helpers

def digits(n_str):
    return [int(ch) for ch in n_str]

def hex_str(s):
    return hex(int(s))[2:].upper()

for name, data in pairs.items():
    imei_str = data["imei_str"]
    code_str = data["code_str"]
    imei_int = int(imei_str)
    code_int = int(code_str)
    imei_hex = hex_str(imei_str)
    code_hex = hex_str(code_str)
    print(f"\n=== {name} ===")
    print(f"IMEI      : {imei_str}  (len={len(imei_str)}, int={imei_int})")
    print(f"IMEI hex  : {imei_hex}")
    print(f"Code      : {code_str}  (len={len(code_str)}, int={code_int})")
    print(f"Code hex  : {code_hex}")
    print(f"IMEI digits: {digits(imei_str)}")
    print(f"Code digits: {digits(code_str)}")
    # Lengths
    print(f"IMEI len  : {len(imei_str)}")
    print(f"Code len  : {len(code_str)}")
    # Difference and ratio
    diff = code_int - imei_int
    ratio = code_int / imei_int if imei_int != 0 else None
    print(f"Diff (C-I): {diff}")
    print(f"Ratio C/I : {ratio:.6f}" if ratio else "Ratio: inf")
    # Modulo small numbers
    for m in [2,3,4,5,7,8,9,10,11,13,16,17,19,32,64,128,256]:
        print(f"  IMEI % {m} = {imei_int % m}  | Code % {m} = {code_int % m}")
    # Check Luhn on IMEI
    def luhn_check(s):
        total = 0
        reverse = s[::-1]
        for i, ch in enumerate(reverse):
            d = int(ch)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    print(f"IMEI Luhn valid: {luhn_check(imei_str)}")
    # Weighted sums
    wsum = sum((i+1)*d for i,d in enumerate(digits(imei_str)))
    print(f"Weighted sum (1..n)*d: {wsum}")
    # Pair groups
    pairs_digits = [digits(imei_str)[i:i+2] for i in range(0,len(imei_str),2)]
    print(f"Digit pairs: {pairs_digits}")
    # Hex digits sum
    hsum = sum(int(ch,16) for ch in imei_hex)
    print(f"Hex digit sum: {hsum}")
    # Bit length
    print(f"IMEI bits: {imei_int.bit_length()}")
    print(f"Code bits: {code_int.bit_length()}")
    # Common non-crypto hash approximations (simulated by simple polynomial)
    # We'll skip actual MD5 here and note in report.

# Cross-comparison
print("\n=== CROSS-COMPARISON ===")
for k,v in pairs.items():
    print(f"{k}: IMEI={v['imei_str']} Code={v['code_str']}")

# Check if IMEI digits reversed equals code or part
for k,v in pairs.items():
    rev = v["imei_str"][::-1]
    print(f"{k} reversed IMEI: {rev}")

# Check if code starts with IMEI first digits etc.
for k,v in pairs.items():
    imei = v["imei_str"]
    code = v["code_str"]
    print(f"{k} IMEI[0:5] vs Code[0:5]: {imei[:5]} vs {code[:5]}")
    print(f"{k} IMEI[0:5] == Code[10:15]: {imei[:5]} == {code[10:15] if len(code)>=15 else 'N/A'}")
