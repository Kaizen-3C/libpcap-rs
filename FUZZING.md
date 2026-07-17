# Differential fuzzing

Coverage-guided fuzzing that generates inputs and checks the Rust port against the upstream C
reference **automatically**, on top of the curated 217-case envelope in `tests/vectors/`
(see `HARNESS.md`). Complements, doesn't replace, the differential test suite: the curated
envelope is the certified claim ("byte-identical on this documented set"), this is open-ended
exploration for anything that set didn't think to cover. Scoped in
[`../DIFFERENTIAL-FUZZING-SCOPE.md`](../DIFFERENTIAL-FUZZING-SCOPE.md).

## What it does

Two fuzz targets, one per module, same design: run one input two ways per iteration, in the
same process.

- **`differential`** (classic-pcap): Rust's public `pcap_check_header`/`pcap_next_packet` API
  (same code path as `differential_driver`) vs. the verbatim-sliced `sf-pcap.c` parser (same
  slice as `cref/assemble.py`, repackaged by `cref/assemble_fuzzlib.py` as an in-process
  callable instead of `_driver.c`'s `main()`).
- **`differential_pcapng`**: Rust's public `pcapng::pcap_ng_check_header`/`pcap_ng_next_packet`
  API (same code path as `differential_driver_pcapng`) vs. the verbatim-sliced `sf-pcapng.c`
  parser (`cref/assemble_fuzzlib_pcapng.py`, mirroring `assemble_fuzzlib.py`).

Both C sides are linked in via `extern "C"` and built with `-fsanitize=address,fuzzer-no-link`
so they contribute to libFuzzer's coverage feedback alongside the Rust side — one `build.rs`
assembles and compiles both.

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
python3 fuzz/seed_corpus.py     # decode tests/vectors/*_inputs.txt into fuzz/corpus/<target>/

# smoke: replay the seed corpus only, no new inputs generated
cargo +nightly fuzz run differential -- -runs=0 fuzz/corpus/differential
cargo +nightly fuzz run differential_pcapng -- -runs=0 fuzz/corpus/differential_pcapng

# fuzz for N seconds (pcapng: cap -max_len, the SHB-insane-length seed is ~2MB and otherwise
# dominates mutation time)
cargo +nightly fuzz run differential -- -max_total_time=60 fuzz/corpus/differential
cargo +nightly fuzz run differential_pcapng -- -max_total_time=60 -max_len=65536 fuzz/corpus/differential_pcapng
```

`fuzz/corpus/` and `fuzz/artifacts/` are gitignored (cargo-fuzz convention) — not checked in;
`seed_corpus.py` regenerates the starting corpus from what *is* checked in.

## Status (2026-07-17)

Both libpcap-rs modules built and validated. Wired into CI (`fuzz-smoke`, 60s per target on
every commit). Not yet run for the multi-hour depth the `fuzz_getimage` libtiff campaign used,
and not yet wired into the pre-RFC gate (see "Process integration" in the scope doc for what
that requires). libogg-rs, libtiff-rs, and giflib-rs targets are not yet built — same pattern,
mechanical repeat.

- **`differential`** (classic-pcap): all 217 curated seeds replay clean. A 15-minute run:
  7.36M executions, ~8,166 exec/s, coverage saturated fast (278→311 edges, 571→933 features —
  small function surface), zero crashes, zero divergences.
- **`differential_pcapng`**: all 226 curated seeds replay clean. A 15-minute run (`-max_len`
  capped at 64KB — one seed is a ~2MB `BT_SHB_INSANE_MAX` case that otherwise dominates mutation
  time): 3.88M executions, ~4,301 exec/s, coverage kept growing through the full run
  (611→690 edges, 1,214→2,009 features — pcapng's larger block-dispatch surface gives the
  mutator more to find than classic-pcap's), zero crashes, zero divergences.
