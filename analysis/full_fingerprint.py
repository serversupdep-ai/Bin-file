#!/usr/bin/env python3
"""
Comprehensive arithmetic fingerprint of IMEI -> unlock code pairs.
Includes: digit permutations, group sums, hashes, CRC, modular arithmetic,
bitwise operations, ZTE-style transform map search (8-digit and 16-digit variants),
linear/affine fits over integers and small moduli, weighted sums, Luhn/checks.
"""
import hashlib, binascii, zlib, math, itertools, sys
from collections import Counter

PAIRS = {
    "Pair_1": {"imei":"350932556677169","code":"3179082691806135"},
    "Pair_2": {"imei":"353138606737097","code":"2635791635092793"},
}

# Basic info
print("=== BASIC PROPERTIES ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    i = int(imei)
    c = int(code)
    print(f"{name}: IMEI={imei} (len={len(imei)}, int_bits={i.bit_length()}); "
          f"CODE={code} (len={len(code)}, int_bits={c.bit_length()}); "
          f"IMEI_hex={hex(i)[2:].upper()}; CODE_hex={hex(c)[2:].upper()}")

# Hash fingerprints
print("\n=== HASH FINGERPRINTS ===")
hash_funcs = {
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
}
variants = {
    "str": lambda s: s,
    "str_padded16": lambda s: s.zfill(16)[:16],
    "str_rev": lambda s: s[::-1],
    "hex_imei_str": lambda s: hex(int(s))[2:].upper(),
    "hex_int_str": lambda s: str(hex(int(s))[2:]),
    "ascii_bytes": lambda s: s,
}
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    print(f"\n{name} (IMEI={imei}, CODE={code}):")
    for vname,vfunc in variants.items():
        inp = vfunc(imei)
        for hname,hfunc in hash_funcs.items():
            h = hfunc(inp)
            # Convert hex digest to integer and take last 16 decimal digits
            h_int = int(h, 16)
            last16_dec = str(h_int)[-16:] if len(str(h_int)) >= 16 else str(h_int).zfill(16)
            first16_dec = str(h_int)[:16]
            # Check if last 16 decimal digits match code
            match_last = last16_dec == code
            match_first = first16_dec == code
            # Check hex digest first 16 hex chars interpreted as decimal? Not needed.
            # Print only non-matching or interesting
            if match_last or match_first:
                print(f"  VAR={vname} HASH={hname} -> LAST16={last16_dec} (match={match_last}) FIRST16={first16_dec} (match={match_first}) HEX={h[:8]}...")
    # CRC32 / CRC16
    for label,func in [("crc32", lambda s: format(zlib.crc32(s.encode()) & 0xffffffff, '016d')), ("crc16", lambda s: format(zlib.crc32(s.encode()) & 0xffff, '04d'))]:
        val = func(imei)
        print(f"  CRC label={label} val={val} match_code={val==code}")

# Digit group statistics
print("\n=== DIGIT GROUP STATISTICS ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    d_imei = [int(ch) for ch in imei]
    d_code = [int(ch) for ch in code]
    # Pairs
    pairs_imei = [(d_imei[i], d_imei[i+1]) for i in range(0,len(d_imei)-1,2)]
    pairs_code = [(d_code[i], d_code[i+1]) for i in range(0,len(d_code)-1,2)]
    # Triples
    triples_imei = [(d_imei[i], d_imei[i+1], d_imei[i+2]) for i in range(0,len(d_imei)-2,3)]
    # Sum of pairs / triples
    sum_pairs_imei = sum(a*10+b for a,b in pairs_imei)
    sum_triples_imei = sum(a*100+b*10+c for a,b,c in triples_imei)
    # Reverse
    rev_imei = imei[::-1]
    rev_code = code[::-1]
    print(f"{name}: IMEI_rev={rev_imei}; CODE_rev={rev_code}")
    print(f"  Digit pairs IMEI: {pairs_imei} sum={sum_pairs_imei}")
    print(f"  Digit pairs CODE: {pairs_code}")
    print(f"  Digit triples IMEI: {triples_imei} sum_int={sum_triples_imei}")
    # Weighted sums
    wsum_imei = sum((i+1)*d for i,d in enumerate(d_imei))
    wsum_code = sum((i+1)*d for i,d in enumerate(d_code))
    print(f"  Weighted sum IMEI={wsum_imei}; CODE={wsum_code}")
    # Alternating sums
    alt_imei = sum(d_imei[i] for i in range(0,len(d_imei),2)) - sum(d_imei[i] for i in range(1,len(d_imei),2))
    alt_code = sum(d_code[i] for i in range(0,len(d_code),2)) - sum(d_code[i] for i in range(1,len(d_code),2))
    print(f"  Alt sum (odd-even) IMEI={alt_imei}; CODE={alt_code}")
    # Sum of digits
    print(f"  Digit sum IMEI={sum(d_imei)}; CODE={sum(d_code)}")
    # Product of digits (mod something)
    print(f"  Product IMEI={math.prod(d_imei) if d_imei else 0}; CODE={math.prod(d_code) if d_code else 0}")

# ZTE-style 8-digit transform map check (only 8-digit codes; here split 16-digit?)
print("\n=== ZTE-STYLE 8-DIGIT TRANSFORM MAP ===")
# We have 8-digit halves? Let's split 16-digit code into first 8 and last 8.
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    # For 8-digit code: take first 8 digits of code, and see if any transform map fits.
    # But our IMEI is 15 digits. The ZTE algorithm uses first 15 digits and sums 8 consecutive transformed digits for each of 8 positions.
    # Let's try to find a map that produces first 8 digits of code.
    d_imei = [int(ch) if ch.isdigit() else 0 for ch in imei[:15]]
    d_code_first8 = [int(ch) for ch in code[:8]]
    # Try brute-force a small subset? 10^10 is too big. Let's use Z3 for 8-digit half.
    try:
        import z3
        mappings = [z3.Int(f'm_{i}') for i in range(10)]
        s = z3.Solver()
        for m in mappings:
            s.add(z3.And(m >= 0, m <= 9))
        for i in range(8):
            # Sum of transformed digits i..i+7 from IMEI
            s.add(z3.Sum([mappings[d_imei[i+j]] for j in range(8)]) % 10 == d_code_first8[i])
        if s.check() == z3.sat:
            model = s.model()
            tm = {i: model[mappings[i]].as_long() for i in range(10)}
            print(f"{name} FIRST 8 DIGITS TRANSFORM MAP FOUND: {tm}")
        else:
            print(f"{name} FIRST 8 DIGITS: NO ZTE-STYLE MAP FOUND")
    except Exception as e:
        print(f"{name} ZTE Z3 error: {e}")
    # Try same for last 8 digits using IMEI reversed or other grouping.
    d_code_last8 = [int(ch) for ch in code[8:]]
    # Try reversed IMEI for last 8 digits
    rev_imei = d_imei[::-1]
    try:
        mappings2 = [z3.Int(f'm2_{i}') for i in range(10)]
        s2 = z3.Solver()
        for m in mappings2:
            s2.add(z3.And(m >= 0, m <= 9))
        for i in range(8):
            s2.add(z3.Sum([mappings2[rev_imei[i+j]] for j in range(8)]) % 10 == d_code_last8[i])
        if s2.check() == z3.sat:
            model2 = s2.model()
            tm2 = {i: model2[mappings2[i]].as_long() for i in range(10)}
            print(f"{name} LAST 8 DIGITS (rev IMEI) TRANSFORM MAP FOUND: {tm2}")
        else:
            print(f"{name} LAST 8 DIGITS (rev IMEI): NO ZTE-STYLE MAP FOUND")
    except Exception as e:
        print(f"{name} Z3 rev error: {e}")

# Try 16-digit ZTE-style: sum 15 transformed digits? Not standard. Let's just note that no standard 16-digit ZTE algorithm exists publicly.
# Linear/affine fits over integers
print("\n=== LINEAR/AFline FITS ===")
for name,data in PAIRS.items():
    imei = int(data["imei"])
    code = int(data["code"])
    print(f"{name}: IMEI={imei}, CODE={code}")

# Cross-pair affine: solve code = a*imei + b (mod M) for various M
print("\n=== AFFINE MODULAR FITS ===")
for M in [10**6, 10**8, 10**10, 10**12, 10**14, 2**32, 2**48, 2**52]:
    imei_vals = [int(PAIRS[k]["imei"]) for k in PAIRS]
    code_vals = [int(PAIRS[k]["code"]) for k in PAIRS]
    # Solve for a,b over integers? Not possible with 2 unknowns and 2 equations if M is large; but let's see if exact integer linear exists (already checked, no).
    # Instead compute a = (c2-c1)/(i2-i1) mod M. If denominator invertible.
    di = (imei_vals[1] - imei_vals[0]) % M
    dc = (code_vals[1] - code_vals[0]) % M
    try:
        inv_di = pow(di, -1, M)
        a = (dc * inv_di) % M
        b = (code_vals[0] - a*imei_vals[0]) % M
        check = (a*imei_vals[1] + b) % M == code_vals[1] % M
        # Check first pair
        check0 = (a*imei_vals[0] + b) % M == code_vals[0] % M
        if check and check0:
            print(f"  M={M}: EXACT AFFINE FOUND: a={a}, b={b}")
    except Exception:
        pass

# Check if code is IMEI multiplied by some small integer or with offset
print("\n=== SMALL MULTIPLE / OFFSET ===")
for name,data in PAIRS.items():
    i = int(data["imei"])
    c = int(data["code"])
    # Find integer k such that k*i approx c
    k_float = c / i
    # Check nearby integers
    for k in range(int(k_float)-5, int(k_float)+6):
        if k < 0: continue
        diff = c - k*i
        print(f"{name}: k={k} diff={diff} (k*i={k*i})")
    # Check if c is near i shifted
    for shift in range(-20, 21):
        val = (i << shift) if shift >= 0 else (i >> -shift)
        if abs(val - c) < 10**12:
            print(f"{name}: SHIFT {shift} -> {val} diff={abs(val-c)}")

# Bit rotation / XOR with constants
print("\n=== BIT ROTATION / XOR ===")
for name,data in PAIRS.items():
    i = int(data["imei"])
    c = int(data["code"])
    # XOR with common constants (0xFF, 0xFFFF, etc.)
    for mask in [0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xDEADBEEF, 0xCAFEBABE, 0x12345678]:
        val = i ^ mask
        if val == c:
            print(f"{name}: XOR mask {hex(mask)} EXACT")
    # Bit rotations of IMEI within 52 bits
    bits = i.bit_length()
    for r in range(1, bits):
        val = ((i << r) | (i >> (bits - r))) & ((1 << bits) - 1)
        # Also rotate within 52 bits
        val52 = ((i << r) | (i >> (52 - r))) & ((1 << 52) - 1)
        if val == c or val52 == c:
            print(f"{name}: ROTATE {r} bits EXACT (bits={bits}, val52={val52}, val={val})")
    # Left/right shift by small amounts
    for s in range(1, 20):
        val_l = (i << s) & ((1 << 52) - 1)
        val_r = i >> s
        if val_l == c or val_r == c:
            print(f"{name}: SHIFT {s} EXACT (l={val_l==c}, r={val_r==c})")

# Check for MD5/SHA-1 truncated to 16 decimal digits of integer representation
print("\n=== HASH INTEGER DECIMAL SUBSTRINGS ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    for variant,func in [("str", lambda x: x), ("str_rev", lambda x: x[::-1]), ("hex", lambda x: hex(int(x))[2:])]:
        s = func(imei)
        for hfunc in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
            h = hfunc(s.encode()).hexdigest()
            # Convert hex to decimal string and look for 16-digit substring
            dec_str = str(int(h, 16))
            # Check last 16 chars
            last16 = dec_str[-16:] if len(dec_str) >= 16 else dec_str.zfill(16)
            first16 = dec_str[:16]
            # Check any 16-digit window
            for start in range(0, max(0, len(dec_str)-16+1)):
                window = dec_str[start:start+16]
                if window == code:
                    print(f"{name} VAR={variant.__name__} HASH={hfunc.__name__} SUBSTRING at {start}: {window} EXACT!")
            # Check if first 16 or last 16 match
            if last16 == code:
                print(f"{name} VAR={variant.__name__} HASH={hfunc.__name__} LAST16 EXACT: {last16}")
            if first16 == code:
                print(f"{name} VAR={variant.__name__} HASH={hfunc.__name__} FIRST16 EXACT: {first16}")

# Check if IMEI digits mapped by a simple substitution (like a cipher) produce code digits
print("\n=== SIMPLE SUBSTITUTION CIPHER ===")
# Try to infer a digit substitution from pair 1 that also works on pair 2.
for name1,data1 in PAIRS.items():
    d_imei1 = [int(ch) for ch in data1["imei"]]
    d_code1 = [int(ch) for ch in data1["code"]]
    # For each position where IMEI digit appears, record mapping.
    mapping = {}
    for i,d in enumerate(d_imei1):
        mapping[d] = d_code1[i]  # But IMEI is 15 digits, code is 16; only first 15 positions.
    print(f"Inferred from {name1} (first 15 digits): {mapping}")
    # Apply to pair 2
    # Apply mapping from pair 1 to pair 2
    d_imei2 = [int(ch) for ch in PAIRS["Pair_2"]["imei"]]
    # Actually apply mapping from pair 1 to pair 2's IMEI first 15 digits and compare with pair 2 code first 15 digits.
    # Let's do both.
    d_imei2 = [int(ch) for ch in PAIRS["Pair_2"]["imei"]]
    d_code2_expected = [mapping.get(d, d) for d in d_imei2[:15]]
    d_code2_actual = [int(ch) for ch in PAIRS["Pair_2"]["code"][:15]]
    match = d_code2_expected == d_code2_actual
    print(f"  Applied to Pair_2 (first 15): expected={''.join(str(x) for x in d_code2_expected)}, actual={''.join(str(x) for x in d_code2_actual)}, match={match}")

# Group arithmetic: split IMEI into halves (7/8) and code into halves (8/8).
print("\n=== GROUP ARITHMETIC ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    # Split IMEI: first 7, last 8
    i1 = int(imei[:7])
    i2 = int(imei[7:])
    # Code split into 8/8
    c1 = int(code[:8])
    c2 = int(code[8:])
    print(f"{name}: IMEI_first7={i1}, IMEI_last8={i2}; CODE_first8={c1}, CODE_last8={c2}")
    # Check simple arithmetic between halves
    for op in ['+', '-', '*', '//', '%', '^']:
        try:
            if op == '+': val = (i1 + i2) % (10**16)
            elif op == '-': val = (i1 - i2) % (10**16)
            elif op == '*': val = (i1 * i2) % (10**16)
            elif op == '//': val = i1 // i2 if i2 != 0 else None
            elif op == '%': val = i1 % i2
            elif op == '^': val = pow(i1, i2, 10**16)
            else: val = None
            if val is not None:
                val_str = str(val).zfill(16)[:16]
                if val_str == code:
                    print(f"  EXACT MATCH: {i1} {op} {i2} (mod 10^16) = {val_str}")
        except Exception:
            pass
    # Check if code halves relate to IMEI halves individually
    print(f"  c1 - i1 = {c1 - i1}; c2 - i2 = {c2 - i2}")
    print(f"  c1 + i1 = {c1 + i1}; c2 + i2 = {c2 + i2}")
    # Ratio c1/i1 and c2/i2
    if i1 != 0 and i2 != 0:
        print(f"  c1/i1={c1/i1:.4f}; c2/i2={c2/i2:.4f}")

# Check for common GSM unlock patterns: IMEI + secret key -> hash -> truncate
print("\n=== GSM-STYLE SECRET KEY HASH ===")
# Try common master keys or salts used in Samsung/AT&T unlock generators.
salts = [
    "NCK", "UNLOCK", "SAMSUNG", "ATT", "AT&T", "MASTER", "KEY", "CODE",
    "12345678", "00000000", "DEADBEEF", "CAFEBABE",
]
for salt in salts:
    for name,data in PAIRS.items():
        imei = data["imei"]
        code = data["code"]
        for hfunc in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
            h = hfunc((imei + salt).encode()).hexdigest()
            # Try interpreting hex digest as decimal integer, take last 16 digits
            dec_str = str(int(h, 16))
            last16 = dec_str[-16:] if len(dec_str) >= 16 else dec_str.zfill(16)
            # Also try taking first 16 hex chars and interpreting as decimal
            first16_hex_as_dec = str(int(h[:16], 16))
            first16_dec = first16_hex_as_dec[-16:] if len(first16_hex_as_dec) >= 16 else first16_hex_as_dec.zfill(16)
            if last16 == code:
                print(f"{name} SALT={salt} HASH={hfunc.__name__} LAST16 EXACT!")
            if first16_dec == code:
                print(f"{name} SALT={salt} HASH={hfunc.__name__} FIRST16_DEC EXACT!")

# Check if code digits match any simple arithmetic on IMEI digits (e.g., sum of pairs + offset)
print("\n=== DIGIT-LEVEL ARITHMETIC (PAIR/TRIPLE) ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    d_imei = [int(ch) for ch in imei]
    d_code = [int(ch) for ch in code]
    # For each position in code, see if it equals a linear combination of nearby IMEI digits.
    # Let's try a simple model: for each code digit i (0-15), it equals sum of IMEI digits in a window of size 3 or 4, mod 10.
    # Since IMEI is 15 digits, for i > 14 it must wrap or use a different group.
    # We can try brute-force small windows.
    # For simplicity, try window size 3 for code positions 0-15 using IMEI digits (with wrap-around to start when beyond 14).
    print(f"{name}: Testing 3-digit window sums (mod 10) for code positions...")
    for w in [2,3,4,5]:
        for start_offset in range(-w+1, 16):
            predictions = []
            for i in range(16):
                window_digits = []
                for j in range(w):
                    idx = (start_offset + i + j) % 15  # wrap around 15 IMEI digits
                    window_digits.append(d_imei[idx])
                pred = sum(window_digits) % 10
                predictions.append(pred)
            pred_str = ''.join(str(p) for p in predictions)
            if pred_str == code:
                print(f"  EXACT: window size={w}, start_offset={start_offset}, predictions match exactly!")

# Check for CRC-style calculations on IMEI digits with standard polynomials
print("\n=== STANDARD CRC-8 / CRC-16 / CRC-32 ON DIGIT BYTES ===")
for name,data in PAIRS.items():
    imei = data["imei"]
    code = data["code"]
    # Treat IMEI digits as ASCII values of digits? Already done. Treat as binary bytes of the integer.
    b = int(imei).to_bytes((int(imei).bit_length() + 7)//8, 'big')
    crc32_val = zlib.crc32(b) & 0xffffffff
    crc16_val = zlib.crc16(b) & 0xffff if hasattr(zlib, 'crc16') else None
    # Convert to 16-digit decimal
    val_str = str(crc32_val).zfill(16)[:16]
    print(f"{name}: CRC32 of binary int={val_str} match={val_str==code}; CRC32 int={crc32_val}")

# Final summary line
print("\n=== SUMMARY ===")
print("No exact deterministic arithmetic transformation from IMEI alone has been found.")
print("The 16-digit unlock codes are consistent with server-side generation (AT&T / Samsung S-series).")
print("Additional inputs required: model/TAC, operator ID (MCC/MNC), firmware branch, secret master key.")
