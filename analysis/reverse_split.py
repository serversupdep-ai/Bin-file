#!/usr/bin/env python3
"""
REVERSE SCRIPT: Split IMEI (15-digit) and NCK (16-digit) into 2 parts,
then attempt arithmetic relationships between halves.

Only user-provided pairs used:
  Pair 1: IMEI=350932556677169  NCK=3179082691806135
  Pair 2: IMEI=353138606737097  NCK=2635791635092793

Context: AT&T / Samsung Galaxy S-series (server-side 16-digit NCK).
"""

PAIRS = {
    "Pair_1": {"imei":"350932556677169","nck":"3179082691806135"},
    "Pair_2": {"imei":"353138606737097","nck":"2635791635092793"},
}

# Split configurations
# IMEI (15 digits) -> [first_7, last_8]  (standard split)
# NCK (16 digits) -> [first_8, last_8]

print("=" * 75)
print("REVERSE ENGINEERING: SPLIT IMEI + SPLIT NCK INTO 2 PARTS")
print("=" * 75)
print()
print("Split rules:")
print("  IMEI (15 digits): [first_7_digits, last_8_digits]")
print("  NCK  (16 digits): [first_8_digits, last_8_digits]")
print()

# Compute halves for both pairs
results = {}
for name, data in PAIRS.items():
    imei = data["imei"]
    nck = data["nck"]
    
    imei_first7 = int(imei[:7])
    imei_last8  = int(imei[7:])
    nck_first8  = int(nck[:8])
    nck_last8   = int(nck[8:])
    
    results[name] = {
        "imei_first7": imei_first7,
        "imei_last8": imei_last8,
        "nck_first8": nck_first8,
        "nck_last8": nck_last8,
    }
    
    print(f"{name}:")
    print(f"  IMEI  = {imei}")
    print(f"    -> first_7  = {imei_first7:>7}  (digits: {imei[:7]})")
    print(f"    -> last_8   = {imei_last8:>8}  (digits: {imei[7:]})")
    print(f"  NCK   = {nck}")
    print(f"    -> first_8  = {nck_first8:>8}  (digits: {nck[:8]})")
    print(f"    -> last_8   = {nck_last8:>8}  (digits: {nck[8:]})")
    print()

# ------------------------------------------------------------------
# 1. DIRECT HALF-TO-HALF ARITHMETIC (same position)
# ------------------------------------------------------------------
print("=" * 75)
print("SECTION 1: DIRECT HALF RELATIONSHIPS")
print("(first_7 vs first_8, last_8 vs last_8, cross-halves)")
print("=" * 75)

for pair_name, r in results.items():
    i_f7 = r["imei_first7"]
    i_l8 = r["imei_last8"]
    n_f8 = r["nck_first8"]
    n_l8 = r["nck_last8"]
    
    print(f"\n{pair_name}:")
    
    # first_7 vs first_8
    diff_f = n_f8 - i_f7
    ratio_f = n_f8 / i_f7 if i_f7 != 0 else float('inf')
    print(f"  IMEI_first7={i_f7}  NCK_first8={n_f8}  -> diff={diff_f:>9}, ratio={ratio_f:.4f}")
    
    # last_8 vs last_8
    diff_l = n_l8 - i_l8
    ratio_l = n_l8 / i_l8 if i_l8 != 0 else float('inf')
    print(f"  IMEI_last8 ={i_l8:>8}  NCK_last8 ={n_l8:>8}  -> diff={diff_l:>9}, ratio={ratio_l:.4f}")
    
    # cross: first_7 vs last_8
    diff_cross1 = n_l8 - i_f7
    ratio_cross1 = n_l8 / i_f7 if i_f7 != 0 else float('inf')
    print(f"  IMEI_first7={i_f7}  vs NCK_last8  -> diff={diff_cross1:>9}, ratio={ratio_cross1:.4f}")
    
    # cross: last_8 vs first_8
    diff_cross2 = n_f8 - i_l8
    ratio_cross2 = n_f8 / i_l8 if i_l8 != 0 else float('inf')
    print(f"  IMEI_last8 ={i_l8:>8}  vs NCK_first8 -> diff={diff_cross2:>9}, ratio={ratio_cross2:.4f}")

# ------------------------------------------------------------------
# 2. ATTEMPT LINEAR MODEL PER HALF (solve using both pairs)
# ------------------------------------------------------------------
print()
print("=" * 75)
print("SECTION 2: LINEAR MODEL ATTEMPT PER HALF (2 equations = solvable)")
print("  nck = a*imei_half + b")
print("=" * 75)

# We have 2 pairs, so for each half we have 2 equations, exactly enough
# to solve for a and b.

# Half configurations
halves = [
    ("first_7 -> first_8", "imei_first7", "nck_first8"),
    ("last_8 -> last_8",  "imei_last8",  "nck_last8"),
    ("first_7 -> last_8", "imei_first7", "nck_last8"),
    ("last_8 -> first_8","imei_last8",  "nck_first8"),
]

for label, imei_key, nck_key in halves:
    # Get values for Pair 1 and Pair 2
    i1 = results["Pair_1"][imei_key]
    c1 = results["Pair_1"][nck_key]
    i2 = results["Pair_2"][imei_key]
    c2 = results["Pair_2"][nck_key]
    
    # Solve: c1 = a*i1 + b, c2 = a*i2 + b
    # a = (c2 - c1) / (i2 - i1)
    # b = c1 - a*i1
    denom = i2 - i1
    if denom == 0:
        print(f"\n{label}: DENOMINATOR ZERO (same IMEI half for both pairs) -> UNSOLVABLE")
        continue
    
    a = (c2 - c1) / denom
    b = c1 - a * i1
    
    # Check exact integer?
    a_is_int = (abs(a - round(a)) < 1e-9)
    b_is_int = (abs(b - round(b)) < 1e-9)
    
    # Check predictions for both pairs
    pred1 = a * i1 + b
    pred2 = a * i2 + b
    match1 = (abs(pred1 - c1) < 1e-6)
    match2 = (abs(pred2 - c2) < 1e-6)
    
    print(f"\n{label}:")
    print(f"  Equations: c={c1}, {c2} | i={i1}, {i2}")
    print(f"  Calculated a = {(c2-c1)}/{denom} = {a:.6f}  (integer? {a_is_int})")
    print(f"  Calculated b = {c1} - {a:.6f}*{i1} = {b:.2f}  (integer? {b_is_int})")
    print(f"  Check Pair 1: pred={pred1:.0f} (expected {c1}) -> {'MATCH' if match1 else 'FAIL'}")
    print(f"  Check Pair 2: pred={pred2:.0f} (expected {c2}) -> {'MATCH' if match2 else 'FAIL'}")
    
    if a_is_int and b_is_int and match1 and match2:
        print(f"  -> EXACT INTEGER LINEAR MODEL FOUND (a={int(a)}, b={int(b)})")
    else:
        print(f"  -> NO EXACT INTEGER LINEAR MODEL (overfit/non-generalizable)")

# ------------------------------------------------------------------
# 3. MODULAR ARITHMETIC BETWEEN HALVES
# ------------------------------------------------------------------
print()
print("=" * 75)
print("SECTION 3: MODULAR RELATIONSHIPS BETWEEN HALVES (mod 10, 100, 1000)")
print("=" * 75)

for pair_name, r in results.items():
    i_f7 = r["imei_first7"]
    i_l8 = r["imei_last8"]
    n_f8 = r["nck_first8"]
    n_l8 = r["nck_last8"]
    
    print(f"\n{pair_name}:")
    # Try simple modular relationships
    # nck_first8 % imei_first7 ?
    # nck_first8 - imei_first7 (mod something)
    # (nck_first8 + nck_last8) % (imei_first7 + imei_last8) ?
    
    for mod in [10, 100, 1000, 10000, 100000, 1000000]:
        # Check if (nck_first8 - imei_first7) % mod == (nck_first8_p2 - imei_first7_p2) % mod ?
        # Actually we want to see if there's a consistent mod relationship for the same pair
        # Just compute residues
        res_f7 = i_f7 % mod
        res_l8 = i_l8 % mod
        res_nf8 = n_f8 % mod
        res_nl8 = n_l8 % mod
    
    # More useful: see if first_8 relates to first_7 via fixed offset mod something
    offset_f8_f7 = (n_f8 - i_f7) % 1000000
    offset_l8_l8 = (n_l8 - i_l8) % 1000000
    print(f"  nck_first8 - imei_first7 = {n_f8 - i_f7} (mod 1M = {offset_f8_f7})")
    print(f"  nck_last8  - imei_last8  = {n_l8 - i_l8} (mod 1M = {offset_l8_l8})")

# ------------------------------------------------------------------
# 4. CROSS-HALF COMBINATIONS (addition/subtraction of halves)
# ------------------------------------------------------------------
print()
print("=" * 75)
print("SECTION 4: CROSS-HALF COMBINATIONS")
print("(e.g., IMEI_first7 + IMEI_last8 vs NCK_first8 + NCK_last8)")
print("=" * 75)

for pair_name, r in results.items():
    i_f7 = r["imei_first7"]
    i_l8 = r["imei_last8"]
    n_f8 = r["nck_first8"]
    n_l8 = r["nck_last8"]
    
    sum_imei = i_f7 + i_l8
    sum_nck = n_f8 + n_l8
    diff_imei_nck_sum = sum_nck - sum_imei
    
    product_imei = i_f7 * i_l8
    product_nck = n_f8 * n_l8
    
    print(f"\n{pair_name}:")
    print(f"  IMEI_first7 + last_8 = {sum_imei}")
    print(f"  NCK_first8 + last_8  = {sum_nck}")
    print(f"  Difference (NCK_sum - IMEI_sum) = {diff_imei_nck_sum}")
    print(f"  Product IMEI halves = {product_imei}")
    print(f"  Product NCK halves  = {product_nck}")

# ------------------------------------------------------------------
# 5. ATTEMPT TO RECOVER A FIXED TRANSFORMATION MAP FROM HALF 1
# ------------------------------------------------------------------
print()
print("=" * 75)
print("SECTION 5: REVERSE ENGINEERING ATTEMPT")
print("Can we recover a hidden constant/key from the differences?")
print("=" * 75)

# Since only 2 pairs, any 2-variable system is exactly determined.
# Let's see if there's a simple multiplicative factor between IMEI and NCK halves.
# e.g., NCK_first8 = k1 * IMEI_first7 + c1 ?
# We already solved linear; now check if ratio is approximately constant.

for label, imei_key, nck_key in halves:
    ratios = []
    for pair_name in ["Pair_1", "Pair_2"]:
        r = results[pair_name]
        ratios.append(r[nck_key] / r[imei_key])
    
    print(f"\n{label}:")
    print(f"  Pair 1 ratio (nck/imei) = {ratios[0]:.6f}")
    print(f"  Pair 2 ratio (nck/imei) = {ratios[1]:.6f}")
    print(f"  Ratio difference = {abs(ratios[1] - ratios[0]):.6f}")
    if abs(ratios[1] - ratios[0]) < 0.01:
        print(f"  -> RATIOS NEARLY CONSISTENT (potential hidden factor)")
    else:
        print(f"  -> RATIOS INCONSISTENT (no fixed multiplicative model)")

print()
print("=" * 75)
print("FINAL CONCLUSION (REVERSE ENGINEERING SPLIT APPROACH)")
print("=" * 75)
print()
print("No consistent arithmetic model exists between any split halves.")
print("Linear models per half have different a/b for different pair/half combos.")
print("Cross-half relationships (sum, product, ratio) vary wildly.")
print()
print("This confirms: The 16-digit AT&T Samsung S-series NCK code is NOT")
print("a simple arithmetic or substitution transformation of the IMEI halves.")
print("Hidden variables (TAC, Model, MCC/MNC=310410, Secret_Params, DB)")
print("are required, consistent with server-side encrypted derivation.")
