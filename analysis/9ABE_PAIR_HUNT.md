# 9ABE / new-suffix pair hunt — "same models, decrypt codes, find hidden key"

Date: 2026-09-05 · Method: exhaustive harvest of every public (service tag →
unlock code) pair for Dell's newest suffix generations, from Reddit (via
arctic-shift archive), badcaps, vinafix, bios-fix.com, YouTube service
listings, and GitHub (pwgen-for-bios issues, DellBIOSTools/Dell-Unlocker
issues). Goal per user: use same-model machines' codes to recover the hidden
key and build the 9ABE keygen.

## 1. Every known 9ABE machine (public)

| Tag | Model | BIOS | Source | Unlock code public? |
|---|---|---|---|---|
| BCBXD14 | Latitude 5440 | 1.30.3 | pwgen-for-bios #324 | NO |
| 6VZW194 | Latitude 3450 | 1.22.1 | pwgen-for-bios #330 | NO |
| 54FW194 | Latitude 3450 | — | vinafix 55448, reddit iks99h | NO (thread unresolved; "motherboard code?" → chip route) |
| J1GVS14 | Latitude 5540 | — | reddit 1mni7p9 (RODBINOSO) | NO ("ou somente via flash?") |
| 13KXL84 | Latitude 5550 | — | reddit iks99h (HiDDeNN_SC) | NO ("alguém já achou a chave?" — nobody has) |
| 6DRBM34 | ? | — | reddit 1mni7p9 | NO |
| 2V7P224 | ? | — | reddit 1mni7p9 | NO |
| 9Z02LX3 | ? | — | reddit iks99h | NO ("impossible de trouver qqchose") |

**Zero 9ABE unlock codes exist anywhere public.** Every resolved case in the
wild was solved by chip dump + patch (programmer) or Dell ownership-transfer.
The only "generators" offered for money (Telegram/WhatsApp sellers) are
scams — documented victims in the same threads (KeyNo539: "paguei a 2
pessoas, me estafaram").

## 2. Who can actually generate what (proven on-thread)

* **Academic_Path5299** (reddit iks99h): runs the PUBLIC engine = our
  `dell_e7a8_pure.py`. Proof: we reproduce 100% of his outputs —
  1JGPCK2 → 67M[kP4k92yG4nMQ + RGRb5UBrrEa8hrGL, BXBGRQ2 (7490) →
  9yZ19ZRG0nZkDkGx + ZIGc2UMjZD[ZcypI, 5957FH2 → XPN[Z7MeDqa[3D4I +
  Ra72s2N92ZFUR3Ek. Refuses 8FC8 ("not possible for 8FC").
* **Captain_Zomaru** (reddit 1mni7p9, Aug 2025): proprietary tool, E7A8
  family ONLY. Solved whaltayr's **Latitude E7270** (code 0tzVtQKtM2bVFBD8
  worked) **after bios-pw.org failed** → his tool holds params for branches
  the public engine lacks. His own words for 8FC8/CF1B/9ABE-class machines:
  "beyond the capabilities of our tools", "never gotten it to work",
  "there isn't a way to get a password for you at this time... desolder the
  bios chip". Tool not public: "I can't provide you the program we use, but
  you might find a similar older version on GitHub" (= DellBIOSTools).
* Commercial services (YouTube/bios-fix.com/badcaps premium): 8FC8/A6E0/
  CF1B/3FE2/1B58 — all chip-dump patch work, no key generation.

## 3. Result of "decrypt the codes" — why pairs cannot yield the key

The E7A8-generation construction (which 9ABE extends) is:

    state = custom-md5-like rounds(tag+E7A8; secret params)   # 32 bytes of
              encodeParams + loopParams + extended table entries
    code  = alphabet[ (sha256(state)[i] + sha256(state)[i+16]) % 72 ]

* The final map is SHA-256-tailed → one-way; codes cannot be inverted.
* The "hidden key" = per-suffix, per-BIOS-branch parameter blocks
  (8×32-bit encodeParams + 4×loopParams + derived table extensions + a
  72-char alphabet permutation ≈ 2^300+ unknowns). With 0 public 9ABE pairs
  (and even thousands of pairs) the params cannot be recovered by search.
* The params exist in exactly two places: Dell's servers and the machine
  firmware image (DellSecurityVaultSmm suffix table). Confirmed again by the
  E7A8 branch matrix below — where public params didn't match, nobody
  "derived" the right ones; a private tool that had them (Zomaru) still
  needed firmware-sourced params to be built.

## 4. E7A8 branch matrix (public-engine params vs. reality)

| Machine class | Public params | Evidence |
|---|---|---|
| Latitude 3x90/5x90/7x90, Precision 3581 (2018-2023) | ✅ work | our 10/10 tags incl. 6 machine-verified |
| Latitude E7270 (2025 thread) | ❌ fail | bios-pw failed; Zomaru's tool worked → different branch params |
| Latitude E7470 (HMHT0N3), E5270 (1RG30G-2E7A8) | ❌ fail | generator codes rejected on-thread |
| Precision 7510 (74WFXF2-6FF1, 2025) | ❌ fail | bios-pw code rejected |
| Latitude 3190 FFC06D3 (Oct-2024 BIOS), 89J3S73 | ❌ fail | proven vs emulated late params (session R-log) |
| 5957FH2 (2025) | ❌ fail | codes (which we reproduce exactly) rejected by machine |

Takeaway: **params are per BIOS-branch**; 9ABE will be the same or worse.
Any keygen must read the target branch's table from that branch's firmware.

## 5. New suffix words catalogued this pass (all unggenererated publicly)

* **8FCA** — C954J64-8FCA (reddit) — 8FC8-family display variant (EC-bound)
* **8FDC8** — BFTF1X2-8FDC8, Latitude 7400 (reddit) — same
* **A6E0, 1B58** — commercial unlock-service list (YouTube, May 2026)
* "Zx0Q" — OCR-garbled, not a real word (craxx21's photo transcription)

## 6. Bottom line + fastest path

Codes from same-model machines do not exist publicly and cannot mathematically
reveal the params. The hidden key is one firmware file away — any ONE of:
Latitude 3450/5440/5540/5550 `BIOS_IMG.rcv` (public dell.com download) or the
extracted DellSecurityVaultSmm PE. Intake pipeline is committed:
`tools/dell_vault_grab.py` (stdlib-only) → suffix table + 9ABE params →
extend `SUFFIX_WORDS` → existing Unicorn harness = keygen; if params NULL →
EC-bound → `tools/dell_8fc8_patch.py` route. Open asks: pwgen-for-bios #331
(+ #324/#330 owners), Project-Bytes #2.
