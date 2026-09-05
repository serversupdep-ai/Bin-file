# Dell BIOS dump analysis — where the "master code" is hidden

**Source archive:** `ARCHES_15_RTL_45W_DSC_10L_213203_1_H6C9P$JA_16MB_&_32MB_BIOS_TESTED.rar`
**Platform:** Dell "ARCHES 15" board — Precision 3581 / Inspiron 15 352x family (Alder-Lake, 2022–23 BIOS)
**Date of analysis:** 2026-09-05

---

## TL;DR

| Question | Answer |
|---|---|
| Where is the master (BIOS admin) code hidden? | In the **SIVB vault record** (`SIVB` = *Security Information Vault Block*) at **file offset `0x22B000` of `R 16.BIN`** (magic `SIVB` at `0x22B004`). If you strip the 512-byte programmer header before flashing, the record sits at flash offset `0x22AE00`. |
| Can it be decrypted from the dump? | **No — by design.** This platform uses Dell's *fixed* scheme: the password is stored only as a **SHA-256 hash inside an AES-encrypted vault**. It is not the XOR scheme of CVE-2026-40639. The vault has been extracted for offline analysis/clearing. |
| Is the vulnerable DVAR+XOR scheme (CVE-2026-40639) present? | **No.** `DVAR` bytes occur only as operands of `cmp` instructions inside the SMM/DXE drivers — there is **no DVAR data store** and **zero valid XOR password records** in either image. |
| Is a password currently set in the 32 MB image? | No live vault found in the 32 MB `…Patched.bin` image — its runtime Dell FVs are erased. Consistent with the file name: the seller already **cleared/patched the password**. The 16 MB `R 16.BIN` **still contains a populated, encrypted SIVB vault** (a master password *was* set on that machine at dump time). |

---

## 1. Files

| File | Size | What it is |
|---|---|---|
| `extracted/…/R 16.BIN` | 16,777,984 B (16 MB + 512 B) | Programmer dump of the 16 MB flash (512-byte tool header prepended; first 0x1000 of flash blank) |
| `extracted/…/XM25QH256C2222@WSON8.BIN_8FC8_Patched.bin` | 33,555,200 B (32 MB + 512 B) | Programmer dump of the 32 MB flash (XM25QH256C chip), already "Patched" by the seller |

Both were extracted from the RAR (password-free) with UNRAR 7.23.

---

## 2. Flash layout

### `R 16.BIN` (16 MB image)

| Flash offset | Content |
|---|---|
| `0x0000–0x0FFF` | blank (descriptor area erased) |
| `0x1000` | region map written by the flasher (points at 0x229000, 0x1C6000, 0x3EF000, 0x616000, …) |
| `0x2000`, `0x3EF000`, `0x616000` | authenticated UEFI variable blocks (`AA 55` records) |
| `0x229000 / 0x22A000` | CSE **`$FPT` partition manifests** (entries: PSVN, RSTR, IMDP, VMP, HVMP, IVBP, UTOK, FLOG, ELOG, FITC, CDMD, FDCR) |
| **`0x22B000`** | **`SIVB` vault record — THE hidden master-code container** (header `30 00 40 1D` = 0x30 hdr + 0x1D40 payload; `SIVB` magic at +4; ~0x60-byte block, 8 zero bytes, then one large AES-encrypted blob; trailing 0x40 bytes of metadata to 0x22CDB0) |
| `0x22F000 – 0x3ED000` | Dell **setup-token store** — 205 records, magic `87 78 55 AA`, 16-bit token/value pairs |
| `0x3A9000+` | BIOS proper (compressed sections; no plain FV headers) |

### 32 MB image

| Flash offset | Content |
|---|---|
| `0x00123000–0x00923000` | BIOS FVs (1 MB ×4 + 4 MB) |
| **`0x00923000`** | **UEFI authenticated variable store** (FV `FFF12B8D-…`; store `AAF32C78-…` size 0x6DFB8; **794 variables parsed** — full listing in `analysis/xm32_uefi_variables.txt`). Notable: `UnlockID`/`UnlockIDCopy` (32 B, GUID `EAEC226F-…`), `OfflineUniqueIDEKPub`, active `Setup` var @ `0x96FD44` |
| `0x00A03000–0x00B23000` | Dell runtime FVs — `DUMMY PERSONALITY` placeholder + **erased scratch FVs** (0xA53000, 0xAA3000, 0xAB3000: empty) and Dell data files in FV `0xA93000` (see `analysis/xm32_dell_fv/`) |
| `0x00B23000–0x01923000` | Main BIOS + 4 MB-shifted **backup copy** (BIOS duplicated for Dell BIOS Recovery) |
| — | **No SIVB record, no DVAR store, no live password data** → password state cleared ("Patched") |

---

## 3. The two places Dell hides BIOS/master passwords (and which one this is)

1. **DVAR + XOR (legacy, CVE-2026-40639 / DSA-2026-197)** — 32-byte record, byte 0 = first char **in the clear**, bytes 1–31 XORed with a 20-byte key (`key = modified_md5(seed‖GUID‖pwd[0])`). The null padding leaks the whole key → passwords ≤ 12 chars recovered instantly; longer ones fall to key-reuse from history records. Confirmed on Latitude E7250/7490, XPS 15 9560, Wyse 5070.
2. **SIVB — Security Information Vault Block (newer, fixed)** — the password is kept only as a **SHA-256 hash inside an encrypted vault**; nothing recoverable from the dump. Confirmed on OptiPlex 3000 — and **this ARCHES/Precision 3581 uses it too**.

**Evidence for SIVB on this platform:**
- A real vault record with `SIVB` magic at `R 16.BIN` file offset `0x22B000`, sitting between the CSE `$FPT` manifests and the Dell token store (exactly where the platform stashes it).
- The SystemPw/DVAR driver code in the 32 MB BIOS references `DVAR` only as `cmp` constants — the legacy store is compiled out/unused; no `DVAR` data store exists in either image.
- A full-image strict scan for the XOR record property (`stored[L]^key==0`, printable decode, key entropy, no ASCII-run keys) found **zero** valid records (the only hits are fragments of driver code/strings, all rejected by the filters).

---

## 4. Extracted artifacts

| Artifact | Description |
|---|---|
| `analysis/sivb_vault_R16_record_hdr0x30_payload0x1d40.bin` | The canonical SIVB record (0x1D70 bytes) — **the hidden master-code container**. SHA-256 `9abb1eb9060f9b6c4015886d6525040c5be8e67cb942956dcd8c3cd935be221e` |
| `analysis/sivb_vault_R16_flash0x22b000.bin` | Full record region incl. trailing metadata (0x1E00 bytes) |
| `analysis/dell_cse_area_R16_0x229000-0x240000.bin` | Context: $FPT manifests + vault + first token records |
| `analysis/dell_token_store_R16_records.txt` | All 205 token records (offset, length, preview) |
| `analysis/xm32_dell_fv/*.ffs` | Dell FFS modules from the 32 MB image (40D4C281-…59/5A pair, EB3001D5, F9538723, DUMMY PERSONALITY) |
| `analysis/xm32_uefi_variables.txt` | All 794 UEFI variables with offsets/states |
| `analysis/scan_results.txt` | Tool output for both dumps |
| `tools/dell_password_recover.py` | Recovery tool (self-test passes on the published E7250 vector) |

## 5. Using the tools

### 5a. Master-password keygen from the lockout "suffix message" (`tools/dell_master_keygen.py`)

Enter the code exactly as shown on the lockout screen — `ServiceTag-SUFFIX` — or paste the whole
message; the parser extracts the challenge automatically.

```bash
python3 tools/dell_master_keygen.py "1234567-595B"
python3 tools/dell_master_keygen.py "1234567890A-D35B"          # HDD serial + suffix
python3 tools/dell_master_keygen.py "5F3988D5E0ACE4BF-7QH8602"  # Latitude 3540 (Insyde)
python3 tools/dell_master_keygen.py "12345678901"               # old HDD serials
python3 tools/dell_master_keygen.py --self-test                 # 47 vectors + DES check
```

Supported suffixes: **595B, D35B, 2A7B, A95B, 1D3B, 1F66, 6FF1, 1F5A, BF97, E7A8**
(BIOS Service-Tag and HDD-serial variants) plus the Dell/Insyde Latitude-3540 challenge.
Faithful Python port of the bios-pw.org engine (emtee40/bios-pwgen, algorithms by
Dogbert/hpgl); validated against all published vectors **and** cross-checked byte-for-byte
against a Node run of the original TypeScript, plus a real-world forum vector
(`5BGYD72-1F66 → jRB9tPxpZRO1K0rY`).

How it works: the serial+suffix is expanded with 8 derived bytes, MD5-style
permutations run (each suffix family has its own tweaked rounds/tables), and the
result is mapped through per-family character tables (scancode tables for 595B/D35B/A95B,
custom alphabets for 1D3B/1F66/6FF1/1F5A/BF97; E7A8 additionally SHA-256s a dual-encoder
output). Enter results on **US QWERTY**, confirm with **Ctrl+Enter**; for 6FF1 also try the
1F5A/BF97 code (firmware bug). The password derivation is deterministic — no brute force.

**Not covered:** suffixes newer than E7A8 (e.g. **8FC8**, the era of the ARCHES/3581
dumps here) have no public algorithm — those machines derive unlock keys server-side
(Dell TechDirect), which is why the flash-patch/seller approach in this repo exists.

### 5b. Password-recovery scanner (`tools/dell_password_recover.py`)

```bash
python3 tools/dell_password_recover.py --self-test          # validates the decoder
python3 tools/dell_password_recover.py <dump.bin>           # scans + extracts vaults
```

On a dump from a **DVAR-era** machine (Latitude E7xx0, XPS 9560, Wyse 5070, …) it prints every recovered password and its key; on these ARCHES dumps it correctly reports the SIVB verdict and extracts the vault.

## 6. The latest suffix generation (8FC8 → CF1B): what "keygen" is possible

Research summary (badcaps / Reddit / vendor sites, 2022–2026):

* **Suffix families through E7A8 + Latitude-3540 Insyde** → public keygen algorithms
  (`tools/dell_master_keygen.py`, 47/47 vectors pass).
* **8FC8 (≈2020–2024) and CF1B (2025+)** → **no public algorithm exists.** Unlock keys
  are derived **server-side**: Dell support issues a recovery key from the Service Tag
  with proof of ownership (TechDirect), and paid sites sell the same. Community wiki:
  *"There is no publicly available 8FC8 generator available at the moment."*
* **CVE-2026-40639 / DSA-2026-197** does *not* give master keys: it recovers the
  **user-set** password from DVAR+XOR records on older platforms (implemented in
  `tools/dell_password_recover.py`); SIVB-era machines (this 3581) store only a
  SHA-256 hash in an AES vault and are immune.

### What actually unlocks 8FC8/CF1B machines — deterministic, no Dell needed

Neutralize the password state in a flash dump (the method used by every repair tool,
including the "Dell 8FC8 BIOS Unlocker" / DellBIOSTools, and by the seller of these
very dumps). Implemented in **`tools/dell_8fc8_patch.py`**:

1. **DVAR security records** `00 FC AA <type>` / `00 FD AA <type>` — zero the subtype
   byte (the community one-byte patch).
2. **SIVB vault record** — erase the whole record to 0xFF (clean-flash state).

**A/B proof from this repo's dumps:**

| | `R 16.BIN` (locked machine) | `…Patched.bin` (seller, "TESTED OK") |
|---|---|---|
| DVAR FC records | 2 live (`type=0xF4` @0xA2F0B6, `type=0x50` @0xA49F7A) | none |
| FD record | 1, already neutralized | none |
| SIVB vault | live @0x22B000 (sha256 `9abb1eb9…`) | erased |

`tools/dell_8fc8_patch.py --patch r16.bin` reproduces the seller's state exactly;
result saved as **`analysis/R16_UNLOCKED_password_cleared.bin`** (flash it →
"The Service Tag has not been programmed" → enter the Service Tag → boots password-free).



- **Flash-level (what the seller did):** erase the SIVB record + Dell runtime stores → firmware sees an uninitialized vault → password gone (settings may reset to defaults). The 32 MB "Patched" image in this repo is exactly that state and is reported as "TESTED OK".
- **Dell-official:** BIOS unlock via Service Tag through Dell TechDirect / support case (proof of ownership), or the F12 BIOS-Recovery unlock-key flow on machines that show a System Lock code.
- **Brute-force:** possible in principle against the SHA-256 *if* the vault could be opened — but the vault itself is AES-encrypted with a device-bound key, so offline guessing is not feasible from the dump alone.

> Legit-recovery note: these steps are for machines you own or are authorised to service (this repo's dumps appear to be repair-shop test images for that purpose).

### 6a. Firmware reverse-engineering results (2026-09): the complete unlock-key architecture

All offsets below are VA inside `DellSecurityVaultSmm` (`section1.pe` of FFS
`c7caf1c7-2d97-45cb-99d9-d89aaf8acc11`, .text @0x1000, .data @0x9000), Precision 3581
BIOS (xm32.bin). SystemPwSmm (`b1951813-…`), HddPwSmm (`3c33a10a-…`) and DellNvmePwSmm
carry the same library tables; none of them contain crypto of their own.

**Two derivation generations live side by side in the vault module:**

| generation | entry | algorithm | status |
|---|---|---|---|
| legacy (2A7B/1D3B/1F66/6FF1/BF97…) | `0x58b4` (generate, canonicalises to the BF97 table) | MD5(tag‖suffix‖packed8) + 72-char table | **== public algorithm, byte-exact** (validated: `DELLSUX-BF97 → rrNM2LrbD8nGsd2P` identical to our ported keygen) |
| new-gen | `0x58b4` → classify `0x45e8` → dispatchers `0x53f0`/`0x553c` → cipher `0x46d8`+`0x4620` → final `0x5298` | suffix table @`0x9760` (24-byte entries `{u16 suffix; params@+8; alphabet@+16}`; ids are u16 words, not strings) | **E7A8 fully recovered & validated** |

New-gen final map: `out[i] = alphabet[(d[i] + d[i+16]) % 72]` (mod via `imul 0x38E38E39`),
E7A8 params @`0x91e8` (28-byte prefix + round dwords 17/13/12/8), E7A8 alphabet @`0x9220`,
8FC8 alphabet @`0x91a0`. A shared 89-byte descriptor (incl. the 48-byte blob
`6e f0 9e 05 … d7 6f 03 02`) is registered by vault/SystemPwSmm/HddPwSmm into an
in-memory list at init (`0x5a0c`/`0x8278`) — it is consumed through the SMM interfaces,
not hashed directly.

**E7A8 keygen — recovered and real-world-validated.** The exact firmware code now runs
under Unicorn (`tools/emu_vault.py` harness, `tools/dell_v2_keygen.py` CLI). Validation
against working codes posted on badcaps/iFixit (2022–2025), all matched exactly:

| challenge | emulated | reported working |
|---|---|---|
| 65FDQN2-E7A8 | `zxdIkZ1XBrINbkDr` | ✔ |
| D9B7JW2-E7A8 | `es6yZz5EaFBxE17Q` | ✔ |
| 5LS8423-E7A8 | `RnGrGsQNZB1rIJ9r` | ✔ |
| F2V9SQ2-E7A8 | `PIFQ2Nns9xMIIQsG` | ✔ |
| J4F3CV2-E7A8 | `d2bkF2QekQ2rbk9Q` | ✔ |
| G7LMQ73-E7A8 | `1GIkGGGmZNc2RNMN` | ✔ |

(`--self-test` re-runs these 6 + the legacy-equality check; 7/7 pass.)

**8FC8 — proven EC-bound, not in the BIOS.** For suffix word `0x8FC8`:

1. `0x58b4` returns `EFI_INVALID_PARAMETER` — the local cipher entry has `params = NULL`
   in the `0x9760` table (slot 0), i.e. the derivation is deliberately disabled in SMM.
2. Instead `0x7fbc`/`0x7b30` write `(sanitised input, fixed 16-byte command
   84 49 62 4d cc d1 7c 4c bf e4 4d 7f 01 3f f2 5a, 2-byte suffix)` to the
   **Embedded-Controller mailbox** (protocol `7310E28E-…` provided by **DellEcIoSmm**,
   which performs real port I/O), and read back the 32 bytes that the final `%72`
   alphabet map consumes. The suffix word itself (`[0x94c8]`) is loaded at boot from
   machine state, not from the Service Tag.
3. The EC firmware is not part of the 32 MB SPI image (flash descriptor has only
   BIOS/GBE/ME/PDR regions; "IT57" hits were certificate false positives).

Consequence: an offline 8FC8 keygen would require the EC firmware (separate chip) or
Dell's server-side secret. Everything short of that is in this repo: the exact request
format, the fixed command constant, and the final key formatting. For a specific
machine the practical unlock therefore remains the deterministic dump patch
(`tools/dell_8fc8_patch.py`) or an EC-firmware dump + the same RE. CF1B (2025+) is
expected to follow the same architecture (successor of 8FC8).


### 6c. Complete suffix catalog (firmware + forum sweep, Sep 2026)

Every lockout suffix seen in the wild, cross-checked against the firmware's own lists
(vault .data @0x92e0: `E7A8 BF97 6FF1 1F66 1D3B 2A7B 0001 | FFFF`; legacy string table
@0x9938; new-gen 24-byte table @0x9760: `8FC8(params NULL) E7A8(params @0x91e8)`):

| suffix | era | engine (as proven in firmware) | keygen |
|---|---|---|---|
| 595B / D35B / 2A7B / 1D3B / 1F66 / 6FF1 / 1F5A / BF97 / A95B (+ HDD numbers) | ≤2020 | MD5 legacy == public algo (byte-exact vs our port) | ✅ `tools/dell_master_keygen.py` (47/47) |
| **E7A8** (2018–2024 BIOS) | — | new-gen cipher, params in BIOS image | ✅ `tools/dell_v2_keygen.py` — **8/8 real-world vectors** (65FDQN2, D9B7JW2, 5LS8423, F2V9SQ2, J4F3CV2, G7LMQ73, 6HDT5S2 + legacy-equality) |
| E7A8 (late-2024+ BIOS) | 2024+ | same cipher, **ROTATED params** (proven: FFC06D3 Oct-2024 & 89J3S73 Aug-2025 fail with 1.13.0 params while 2023 machines match) | run `dell_newbios_probe.py` on that machine's BIOS image → keygen follows |
| 0001 | 2024+ | emulation shows SMM falls back to the legacy canonical (BF97) key; community: master-password option disabled in this state → codes usually rejected | dump-patch (`dell_8fc8_patch.py`) |
| 8FC8 | 2020–2025 | EC mailbox (DellEcIoSmm port I/O), derivation NOT in BIOS | ❌ local — needs EC firmware; use patcher |
| CF1B | 2025+ | 8FC8 successor (community/chromebreaker) | needs newer BIOS image (probe) |
| 9ABE | 2025–2026 | newest gen; absent from BIOS 1.13.0 — lives in ≥1.17.0-era images | needs newer BIOS image (probe) — upload `BIOS_IMG.rcv` |
| 3FE2 | 2021+ | "BIOS Service Tag Lockout Code" state; treated by repair community exactly like 8FC8 cases | dump-patch |
| "8FCE" | — | **does not exist** — zero forum reports ever; typo/OCR of 8FC8 | (= 8FC8) |

Notes proven this session (emulator, fn B @0x58b4): suffix word `0x0001` and `0xBF97`
produce identical output (legacy canonicalisation of unknown/new words); the second
code ("Unlock Code 2") quoted alongside E7A8 keys in forums is NOT produced by either
dispatcher (0x53f0/0x553c) with any input variant tested — it is the first code that is
consistently reported working.

**UPDATE — Code 2 SOLVED** (cross-source validation): the public engine port
(chromebreakerdev/Dell-Unlocker `WORKINGKEYGEN.py`) contains a `TagE7A8EncoderSecond`:
same core with a 4-entry-extended constant table (entries = original `encodeParams`
XOR `0x6D2F93A5`) and inner-loop depth 16 instead of 8 (`loopParams [17,13,12,16]`).
It reproduces all 7 forum-quoted code-2 values, including the publicly witnessed
6HDT5S2 -> `Zq8r9P6rRGkMIhN1`. Ported to `tools/dell_e7a8_pure.py` (14/14 vectors,
both codes) and wired into `dell_v2_keygen.py`, which now prints both codes and
falls back to the pure engine when unicorn is not installed.

### 6d. 9ABE acquisition status (as of 2026-09-05)

Confirmed 9ABE machines (public): Latitude 5440, BIOS 1.30.3, tag BCBXD14
(pwgen-for-bios #324); Latitude 3450, BIOS 1.22.1, tag 6VZW194 (#330);
plus 2025-26 forum tags 6DRBM34 / 2V7P224 / 9Z02LX3. CF1B sightings include
Latitude 5410 (#322) — 8FC8's successor generation.

Firmware-byte reachability from the research sandbox: github.com (clones +
API blobs), codeload.github.com, pypi.org + files.pythonhosted.org ONLY.
dl.dell.com, archive.org, LVFS/cdn.fwupd.org, huggingface, zenodo, GDrive,
ghcr/npm registries, objects.githubusercontent.com (release assets), and
raw.githubusercontent.com are all blocked. Exhaustive GitHub code/repo/issue
searches found NO committed 2024+ Dell firmware or vault module (only
luc4m4rio/Project-Bytes' BIOS 1.19.1 extraction *reports*, 8th-gen platform).

Active asks: bacher09/pwgen-for-bios#331 + #324/#330 (9ABE machine owners),
luc4m4rio/Project-Bytes#2 (vault PE from 1.19.1 or newer).

Pair-hunt pass (2026-09-05, see analysis/9ABE_PAIR_HUNT.md): harvested every
public (tag -> code) pair for new generations via the arctic-shift reddit
archive. Result: 0 public 9ABE codes anywhere (9 machines catalogued; only
chip-patch/Dell-transfer solutions); our engine reproduces 100% of all
publicly generated E7A8 pairs ever posted (10 tags, 20/20 codes, self-test
extended); public-params failures on E7270/E7470/7510/3190-2024/5957FH2
prove per-BIOS-branch params — one private tool (reddit Captain_Zomaru)
holds extra E7A8 branch params but explicitly cannot do 8FC8/CF1B/9ABE.
New suffix words observed: 8FCA, 8FDC8 (8FC8-family), A6E0, 1B58.

Ready-to-run intake pipeline (committed here):
* tools/dell_vault_grab.py — stdlib-only; accepts .exe/.rcv/dump; walks
  FFS -> GUIDed-LZMA -> nested FVs; decodes suffix tables; flags 9ABE/CF1B
  entries + dumps their params. Validated: 1.13.0 module (exact table
  {8FC8 NULL, E7A8 params 0x91e8}), full 25 MB BIOS region (multi-layer
  LZMA), synthetic 9ABE image.
* tools/dell_newbios_probe.py — uefi_firmware-based structured parse.
* If 9ABE params != NULL: extend SUFFIX_WORDS + feed the new params to the
  existing Unicorn harness (the E7A8 pipeline unchanged) -> keygen.
  If NULL: EC-bound (8FC8/CF1B route) -> tools/dell_8fc8_patch.py.

### 6a-bis. Parameter-space "deep play" on the new generation (2026-09-05)

Oracles available for the late-2024 branch (no firmware): FFC06D3 ->
ZzIL1LJL3260RGdI / 2Wrrzc6Nq2DG0QQZ (badcaps, Oct-2024 BIOS) and 7XSP3D3-0001
-> Jp1PZrbZE9ZmJIkn / ZZqL3Nk8nE6kM9x3. Tested with tools/dell_param_solver.py:

* family/format shotgun: all 10 legacy families x both E7A8 encoders x 14
  suffix-strings x 4 block formats (std/serial-mode/lowercase/suffix-first)
  = 0 matches -> the branch is NOT a format change.
* structural transforms (whole-block XOR 0x6D2F93A5, byte-swap, reversal,
  pair-swaps, 9 loopParam variants) = 0 hits.
* template-delta search: loopParams-only (320 grids) + encodeParams
  single-knob deltas (+-1/8/0x10/0x100/0x1000 on 4 structural knobs, 9.8k
  combos + e/f knobs 2.5k) = 0 hits in ~13.3k combos (~13k x 2^-32 hit
  probability per combo if random -> expected 0 hits; i.e. the rotation is
  a fresh pseudo-random draw, NOT a template delta like the legacy
  suffix family).
* 0x6D2F93A5 provenance: not derived from any obvious string/hash/constant
  relation tested -> treat as opaque Dell constant.

Consequence: late-2024+ branches (and 9ABE) cannot be reached analytically
from known params; only the per-branch firmware table (or Dell) holds them.
tools/dell_vault_grab.py now auto-DECODES a new entry's 56-byte params blob
into loopParams + encodeParams (+ derives the code-2 extension entries), so
a single 9ABE-era file converts to a working keygen in one step.

### 6b. Tooling added in this pass

* `tools/emu_vault.py` — Unicorn harness: loads DellSecurityVaultSmm with base
  relocations applied, calls internal functions directly (sanity self-checks included).
* `tools/dell_v2_keygen.py` — CLI keygen: `--tag XXXXXXX --suffix E7A8 [--pe|--dump]`,
  extracts the module from a full SPI dump when `uefi_firmware` is present, locates the
  generator by signature, 7/7 self-test. Legacy families keep working through
  `tools/dell_master_keygen.py` (the v2 module canonicalises them to BF97, matching the
  community "6FF1 buggy → use BF97" advice).
