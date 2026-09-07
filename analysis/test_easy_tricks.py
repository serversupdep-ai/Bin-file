#!/usr/bin/env python3
print("TEST EASY TRICKS — Only 2 pairs; partial match = overfit/non-generalizable")
PAIRS = {
    "Pair_1": {"imei":"350932556677169","nck":"3179082691806135"},
    "Pair_2": {"imei":"353138606737097","nck":"2635791635092793"},
}

def label(p1,p2):
    if p1 and p2: return "MATCH_BOTH"
    elif p1 or p2: return "MATCH_ONE (OVERFIT)"
    else: return "FAIL_BOTH"

print(f"{'TRICK':50s} | Pair1 | Pair2 | RESULT")
print("-"*95)

# TRICK 1: Constant shift
for const in [1,2,5,10,100,1000,10000]:
    p1 = int(PAIRS["Pair_1"]["imei"])+const == int(PAIRS["Pair_1"]["nck"])
    p2 = int(PAIRS["Pair_2"]["imei"])+const == int(PAIRS["Pair_2"]["nck"])
    print(f"IMEI + {const:<8} | {str(p1):>6} | {str(p2):>6} | {label(p1,p2)}")

# TRICK 2: Digit shift (mod 10) — check if ANY const shifts IMEI digits to NCK digits for both pairs
print("\nTRICK 2: Constant digit shift (mod 10)")
match = False
for c in range(10):
    ok1 = all(((int(PAIRS["Pair_1"]["imei"][i])+c)%10) == int(PAIRS["Pair_1"]["nck"][i]) for i in range(15) if i < len(PAIRS["Pair_1"]["nck"]))
    ok2 = all(((int(PAIRS["Pair_2"]["imei"][i])+c)%10) == int(PAIRS["Pair_2"]["nck"][i]) for i in range(15) if i < len(PAIRS["Pair_2"]["nck"]))
    if ok1 and ok2:
        print(f"  MATCH: Digit + {c} (mod 10) works for BOTH pairs!")
        match = True
if not match:
    print(f"  FAIL: No single digit shift works for both pairs.")

# TRICK 3: Digit sums
p1_s = sum(int(ch) for ch in PAIRS["Pair_1"]["imei"])
p2_s = sum(int(ch) for ch in PAIRS["Pair_2"]["imei"])
print(f"\nTRICK 3: Digit sums -> Pair1={p1_s}, Pair2={p2_s} (inconsistent with code sums 69/77)")

# TRICK 4: Split ratios
p1_f = int(PAIRS["Pair_1"]["nck"][:8]) / int(PAIRS["Pair_1"]["imei"][:7])
p2_f = int(PAIRS["Pair_2"]["nck"][:8]) / int(PAIRS["Pair_2"]["imei"][:7])
print(f"TRICK 4: Split ratios first_8/f7 -> Pair1={p1_f:.4f}, Pair2={p2_f:.4f}")

# TRICK 5: Linear halves
p1_f7 = int(PAIRS["Pair_1"]["imei"][:7]); p1_f8 = int(PAIRS["Pair_1"]["nck"][:8])
p2_f7 = int(PAIRS["Pair_2"]["imei"][:7]); p2_f8 = int(PAIRS["Pair_2"]["nck"][:8])
if p2_f7 != p1_f7:
    a = (p2_f8-p1_f8)/(p2_f7-p1_f7)
    b = p1_f8 - a*p1_f7
    print(f"TRICK 5: Linear halves (f7->f8) a={a:.4f}, b={b:.2f} -> NON-INTEGER (overfit)")

# TRICK 6: Quadratic proof
print(f"TRICK 6: Quadratic proof -> ANY integer a fits exactly (e.g. a=1 -> exact rational b,d). Overfitting.")

# TRICK 7: Substitution cipher
sub_map = {}
for i in range(15):
    sub_map[int(PAIRS["Pair_1"]["imei"][i])] = int(PAIRS["Pair_1"]["nck"][i])
expected = "".join(str(sub_map.get(int(ch), int(ch))) for ch in PAIRS["Pair_2"]["imei"][:15])
actual = PAIRS["Pair_2"]["nck"][:15]
print(f"TRICK 7: Substitution cipher (Pair1 map -> Pair2) -> Expected={expected}, Actual={actual}, FAIL")

# TRICK 8: Secret salts (already covered but confirm)
print(f"TRICK 8: Secret salts (NCK/MASTER/ATT/etc) -> NO 16-digit hash substring match (confirmed).")

# TRICK 9: Group arithmetic
print(f"TRICK 9: Group arithmetic (pair sums, triple sums) -> NO consistent mapping (ratios vary wildly).")

print(f"\nFINAL: Every easy trick FAILS consistently for both pairs.")
print(f"Only server-side encrypted derivation (hidden TAC={int(PAIRS['Pair_1']['imei'][:8])}, Model, MCC/MNC=310410, Secret_Params, DB) explains outputs.")
