# Differential fuzzing

Coverage-guided fuzzing that generates inputs and checks the Rust port against the upstream C
reference **automatically**, on top of the curated 217-case envelope in `tests/vectors/`
(see `HARNESS.md`). Complements, doesn't replace, the differential test suite: the curated
envelope is the checked claim ("byte-identical on this documented set"), this is open-ended
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

## Findings

**2026-07-18, ~3.2M executions into an 8-hour overnight run of `differential_pcapng`** (the
initial 15-minute runs didn't go deep enough to hit this): a real panic in the checked port,
`pcapng.rs`'s timestamp fraction scaling (`finish_packet`, the `ScaleUpDec`/`ScaleUpBin`/
`ScaleDownBin` arms) — `frac *= scale_factor` / `frac *= user_tsresol` overflow `u64` on
adversarial input (`tsresol` comes from an attacker-controlled binary-exponent `if_tsresol` IDB
option, up to `1u64 << 63`, so `frac = t % tsresol` can be large enough that these multiplies
genuinely overflow). Upstream C's `uint64_t` arithmetic here is naturally wrapping — no UB, no
crash — and Rust's *release* build (the one actually shipped, `overflow-checks` off by default)
already wraps identically, so this was **never an observable behavioral divergence** — but
cargo-fuzz always enables debug-assertions, and so would a plain `cargo build` (no `--release`)
of this crate as someone's dependency, which would panic on the same malicious pcapng file.
Fixed by switching the two multiplies to explicit `.wrapping_mul(...)`, making the C-faithful
wraparound intent explicit instead of relying on the release profile's default. Re-verified
217+226/226 byte-identical against both pinned tarballs after the change.

## Status (2026-07-18)

Both libpcap-rs modules built and validated, one real port bug found and fixed (above — took
overnight-depth fuzzing, not the initial 15-minute runs, to surface). Wired into CI
(`fuzz-smoke`, 60s per target on every commit). The sibling ports carry differential fuzz
targets too (see each one's own `FUZZING.md`). Not yet wired into the pre-RFC gate
(see "Process integration" in the scope doc for what that requires).

- **`differential`** (classic-pcap): all 217 curated seeds replay clean. A 15-minute run:
  7.36M executions, ~8,166 exec/s, coverage saturated fast (278→311 edges, 571→933 features —
  small function surface), zero crashes, zero divergences. An 8-hour overnight run is in
  progress as of this writing.
- **`differential_pcapng`**: all 226 curated seeds replay clean. A 15-minute run (`-max_len`
  capped at 64KB — one seed is a ~2MB `BT_SHB_INSANE_MAX` case that otherwise dominates mutation
  time): 3.88M executions, ~4,301 exec/s, coverage kept growing through the full run
  (611→690 edges, 1,214→2,009 features — pcapng's larger block-dispatch surface gives the
  mutator more to find than classic-pcap's), zero crashes, zero divergences. An overnight
  (8-hour) run found the timestamp-scaling overflow above at ~3.2M executions; a second
  overnight run is in progress after the fix.
