"""Bootstrap fuzz/corpus/<target>/ from the checked-in curated envelopes
(tests/vectors/*_inputs.txt) — hex-encoded cases decoded to raw files, one per fuzz target.
corpus/ is gitignored (cargo-fuzz convention), so a fresh clone needs to run this once before
fuzzing; libFuzzer will grow the corpus from here via mutation.

Usage: python3 fuzz/seed_corpus.py
"""
import binascii
import os

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "tests", "vectors")

TARGETS = {
    "differential": "pcap_inputs.txt",
    "differential_pcapng": "pcapng_inputs.txt",
}

for target, inputs_file in TARGETS.items():
    src = os.path.join(VECTORS, inputs_file)
    dst = os.path.join(HERE, "corpus", target)
    os.makedirs(dst, exist_ok=True)
    n = 0
    with open(src, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = binascii.unhexlify(line)
            with open(os.path.join(dst, f"seed_{n:04d}"), "wb") as out:
                out.write(data)
            n += 1
    print(f"seeded {n} cases into {dst}")
