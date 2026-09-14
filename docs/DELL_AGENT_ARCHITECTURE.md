# Dell FC1B agent architecture map

The checkout is a small collection of standalone Python research utilities and
firmware artifacts; it has no package, dependency manifest, or orchestration
framework. Existing `tools/` scripts are useful historical probes but include
mutation/key-generation workflows, so the new read-only entry point is kept
separate and reuses no destructive code.

`agent.py` is the stable CLI. `dell_3090_fc1b_recovery.py` contains deterministic
stages: hash and entropy -> cautious SPI layout -> FV discovery -> heuristic EFI
variable records -> validated DVAR-store discovery -> complete null-padding XOR
validation -> FC1B correlation -> JSON/text evidence. All extracted evidence is
written below the requested output directory; the input is opened read-only.

`tests/test_dell_agent.py` supplies synthetic vectors for the published DVAR
shape, wrong-key/corruption rejection, store scoping, and incomplete dumps.
The agent does not import the existing patchers or key generators and does not
assume FC1B is a key.
