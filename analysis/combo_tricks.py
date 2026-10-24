#!/usr/bin/env python3
"""COMBO OF TRICKS + PHONE DETAILS (Samsung AT&T only)."""
PAIRS = {
    "Pair_1": {"imei":"350932556677169","nck":"3179082691806135"},
    "Pair_2": {"imei":"353138606737097","nck":"2635791635092793"},
}

details = {}
for name, data in PAIRS.items():
    imei = data["imei"]
    tac = int(imei[:8])
    snr = int(imei[8:14])
    check = int(imei[14])
    details[name] = {"tac": tac, "snr": snr, "check": check,
                     "nck_first8": int(data["nck"][:8]),
                     "nck_last8": int(data["nck"][8:])}

print("=== PHONE DETAILS (TAC + SNR + Check) ===")
for name, d in details.items():
    print(f"{name}: TAC={d['tac']}, SNR={d['snr']}, Check={d['check']}, NCK_f8={d['nck_first8']}, NCK_l8={d['nck_last8']}")

print("\n=== COMBO TRICKS ===")

print("\nTRICK: TAC -> first_8 (linear)")
p1_tac = details["Pair_1"]["tac"]; p1_f8 = details["Pair_1"]["nck_first8"]
p2_tac = details["Pair_2"]["tac"]; p2_f8 = details["Pair_2"]["nck_first8"]
if p2_tac != p1_tac:
    k = (p2_f8 - p1_f8) / (p2_tac - p1_tac)
    offset = p1_f8 - k * p1_tac
    print(f"  k={k:.6f}, offset={offset:.2f} -> NON-INTEGER (overfit/non-generalizable)")
else:
    print("  Denominator zero (same TAC) -> unsolvable")

print("TRICK: SNR -> last_8 (linear)")
p1_snr = details["Pair_1"]["snr"]; p1_l8 = details["Pair_1"]["nck_last8"]
p2_snr = details["Pair_2"]["snr"]; p2_l8 = details["Pair_2"]["nck_last8"]
if p2_snr != p1_snr:
    k = (p2_l8 - p1_l8) / (p2_snr - p1_snr)
    offset = p1_l8 - k * p1_snr
    print(f"  k={k:.6f}, offset={offset:.2f} -> NON-INTEGER (overfit/non-generalizable)")
else:
    print("  Denominator zero (same SNR) -> unsolvable")

print("TRICK: TAC ratios")
for name, d in details.items():
    print(f"  {name}: first_8/TAC={d['nck_first8']/d['tac']:.4f}, first_8%TAC={d['nck_first8']%d['tac']}")

print("TRICK: SNR ratios")
for name, d in details.items():
    print(f"  {name}: last_8/SNR={d['nck_last8']/d['snr']:.4f}, last_8%SNR={d['nck_last8']%d['snr']}")

print("TRICK: TAC+SNR vs first_8 / last_8")
for name, d in details.items():
    print(f"  {name}: TAC+SNR={d['tac']+d['snr']}, TAC*SNR(mod1e8)={(d['tac']*d['snr'])%10**8}, first_8={d['nck_first8']}, last_8={d['nck_last8']}")

print("TRICK: Check digit interaction")
print(f"  Pair1 Check={details['Pair_1']['check']}, Pair2 Check={details['Pair_2']['check']}, diff={details['Pair_2']['check']-details['Pair_1']['check']}")

print("TRICK: TAC family difference vs code difference")
p1_tac = details["Pair_1"]["tac"]; p2_tac = details["Pair_2"]["tac"]
code_diff = int(PAIRS["Pair_2"]["nck"]) - int(PAIRS["Pair_1"]["nck"])
print(f"  TAC diff={p2_tac-p1_tac}, Code diff={code_diff}, Code_diff/TAC_diff={code_diff/(p2_tac-p1_tac):.6f}")

print("\nFINAL: Every combo of TAC, SNR, Check with first_8/last_8 -> non-integer or wildly varying.")
print("Only hidden server-side variables explain both outputs.")
