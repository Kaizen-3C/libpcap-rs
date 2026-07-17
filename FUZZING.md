# Differential fuzzing

Coverage-guided fuzzing that generates inputs and checks the Rust port against the upstream C
reference **automatically**, on top of the curated 217-case envelope in `tests/vectors/`
(see `HARNESS.md`). Complements, doesn't replace, the differential test suite: the curated
envelope is the certified claim ("byte-identical on this documented set"), this is open-ended
exploration for anything that set didn't think to cover. Scoped in
[`../DIFFERENTIAL-FUZZING-SCOPE.md`](../DIFFERENTIAL-FUZZING-SCOPE.md).

## What it does

`fuzz/fuzz_targets/differential.rs` runs one input two ways per iteration, in the same process:

- **Rust:** the public `pcap_check_header`/`pcap_next_packet` API (same code path as
  `differential_driver`).
- **C:** the verbatim-sliced `sf-pcap.c` parser (same slice as `cref/assemble.py`, repackaged by
  `cref/assemble_fuzzlib.py` as an in-process callable instead of `_driver.c`'s `main()`), linked
  in via `extern "C"` and built with `-fsanitize=address,fuzzer-no-link` so it contributes to
  libFuzzer's coverage feedback alongside the Rust side.

A mismatch between the two traces — or a Rust panic (e.g. an unchecked arithmetic overflow,
which is a crash/DoS even in `forbid(unsafe_code)` code) — is a libFuzzer crash with a minimized
repro. ASan on the C side additionally catches memory-safety bugs in the *reference* itself.

## Running it

Linux/WSL only (cargo-fuzz + ASan tooling; not attempted on native Windows).

```bash
# one-time setup
rustup toolchain install nightly
cargo install cargo-fuzz
bash scripts/regen_goldens.sh   # populates cref/_build/libpcap-1.10.5 (build.rs needs it)
python3 fuzz/seed_corpus.py     # decode tests/vectors/pcap_inputs.txt into fuzz/corpus/differential/

# smoke: replay the seed corpus only, no new inputs generated
cargo +nightly fuzz run differential -- -runs=0 fuzz/corpus/differential

# fuzz for N seconds
cargo +nightly fuzz run differential -- -max_total_time=60 fuzz/corpus/differential
```

`fuzz/corpus/` and `fuzz/artifacts/` are gitignored (cargo-fuzz convention) — not checked in;
`seed_corpus.py` regenerates the starting corpus from what *is* checked in.

## Status (2026-07-17)

Prototype built and validated for **libpcap-rs classic** (`pcap_check_header`/
`pcap_next_packet`) — first crate in the per-crate rollout order in
`DIFFERENTIAL-FUZZING-SCOPE.md`. All 217 curated-envelope seeds replay with zero mismatches.
A 60-second exploratory run reached ~8,000 exec/s (~484k total runs), grew coverage from the
seed corpus (278→309 edges, 571→907 features), zero crashes, zero divergences. Not yet run
for the multi-hour depth the `fuzz_getimage` libtiff campaign used, and not yet wired into CI
or the pre-RFC gate (see "Process integration" in the scope doc for what that requires).
pcapng, libogg-rs, libtiff-rs, and giflib-rs targets are not yet built.
