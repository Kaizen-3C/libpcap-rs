"""Bootstrap fuzz/corpus/differential/ from the checked-in curated envelope
(tests/vectors/pcap_inputs.txt) — 217 hex-encoded cases decoded to raw files. corpus/ is
gitignored (cargo-fuzz convention), so a fresh clone needs to run this once before fuzzing;
libFuzzer will grow the corpus from here via mutation.

Usage: python3 fuzz/seed_corpus.py
"""
import binascii
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "tests", "vectors", "pcap_inputs.txt")
DST = os.path.join(HERE, "corpus", "differential")

os.makedirs(DST, exist_ok=True)
n = 0
with open(SRC, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        data = binascii.unhexlify(line)
        with open(os.path.join(DST, f"seed_{n:04d}"), "wb") as out:
            out.write(data)
        n += 1
print(f"seeded {n} cases into {DST}")
