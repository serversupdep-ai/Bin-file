# GSM FORUM FINDING — Samsung 16-Digit Code Structure

Source: https://community.ee.co.uk/t5/Android-Devices/16-Digit-Sim-unlock-code-for-Samsung-handset-not-working/td-p/1461587

Key finding from forum (user DeKronk, Explorer, Thursday Oct 31, 2024):

> "With the 16 digit unlock code you receive, the first 8 digits are the unlock code,
> the last 8 digits are what is known as the MCK or unfreeze code.
> So for unlocking you should only enter the first 8 digits not the full 16 digit code.
> If you enter the unlock code incorrectly too many times the phone would freeze
> and prevent any further attempts until the MCK code was used which is the last 8."

IMPLICATION FOR OUR PAIRS:

| Pair | Full 16-digit | NCK (first 8) | MCK (last 8) |
|---|---|---|---|
| Pair 1 | 3179082691806135 | 31790826 | 91806135 |
| Pair 2 | 2635791635092793 | 26357916 | 35092793 |

This confirms:
- The code is NOT a single 16-digit derivation from IMEI.
- It is a COMBINED output: NCK (network unlock) + MCK (master/unfreeze) concatenated.
- Any attempt to derive the full 16 digits as one mathematical function of IMEI will fail,
  because it combines TWO independent codes with potentially different derivation algorithms.
- The substitution-window partial match for Pair 1 first 8 (31790826) applies ONLY to the NCK half,
  not the MCK half (91806135) — consistent with UNSAT for last 8.
- Pair 2's first 8 (26357916) has no substitution map (UNSAT) — confirming the NCK algorithm
  requires hidden variables (model, TAC, MCC/MNC, secret params, server-side database) and is NOT
  a pure IMEI-only derivation.

This forum finding does NOT provide a mathematical algorithm, but it explains the structural
reason why full-16-digit arithmetic models consistently fail (UNSAT) and why split-half
analysis shows wildly inconsistent ratios between NCK and MCK halves.
