# libpcap-rs

A memory-safe Rust port of two **libpcap 1.10.5** savefile parsers — the untrusted-input paths
that turn a hostile capture file into validated packet records:

- **classic-pcap** (`src/sf-pcap.c`): `pcap_check_header` (file-header validation, byte-order
  detection, version/linktype/reserved-field checks) and `pcap_next_packet` (per-record
  parsing, timestamp scaling, caplen/len swap heuristics, and the **caplen/snapshot bounds
  checks that are libpcap's historical CVE surface**).
- **pcapng** (`src/sf-pcapng.c`, module [`pcapng`](src/pcapng.rs)): `pcap_ng_check_header`
  (Section Header Block detection, byte-order/version validation, first-section Interface
  Description Block) and `pcap_ng_next_packet` (the EPB/SPB/PB/IDB/SHB block loop, per-block
  length/trailer sanity, per-interface timestamp-resolution scaling, and the same
  caplen/snapshot bounds checks in the pcapng block-parser's terms).

The entire crate is **`#![forbid(unsafe_code)]`** and has **zero dependencies**.

## Provenance

- Ported from `libpcap-1.10.5.tar.gz`, sha256
  `37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0` (tcpdump.org).
- Licensed BSD-3-Clause, identical to upstream; see `LICENSE` (libpcap's, UC Regents /
  tcpdump.org copyright retained).

## Scope

This is the **classic-pcap and pcapng savefile readers**, not all of libpcap. In scope: the
file-header and block/record parsers that turn untrusted `.pcap`/`.pcapng` bytes into
validated packet headers + captured data. Out of scope (and not ported): live capture (OS
syscalls, BPF), the full DLT/linktype-to-DLT mapping table, and the encoder/dumper (classic
`savefile.c` write path or pcapng's block-writer). The parsers are the security-relevant
subset — it's what runs first on a hostile file.

## Certification methodology

This port was not reviewed into correctness — it was **measured** into it. The upstream C
parser and the Rust port are both driven by an identical op-script harness (one hex-encoded
`.pcap` file per stdin line) over a declared envelope, and their complete observable stdout —
parsed header fields, per-packet caplen/len/timestamp/data-hash, **and the verbatim upstream
diagnostic strings on every rejection** — is byte-compared against the upstream C build:

| Envelope | Cases | What it exercises | Result |
|---|---|---|---|
| `tests/vectors/pcap_*` | 217 | valid files across all versions (2.0–2.4, 543.0), link types, little/big-endian, and the three magic variants (standard, nanosecond, Kuznetzov-patched-header); snaplen edges (0→clamp, 1, MAXIMUM_SNAPLEN, over); caplen/len swap heuristics; **the caplen>max and caplen>snapshot bounds checks** (fired 75× across the corpus); **plus** an adversarial half — bad magic, single-byte corruption at every header offset, truncation at every field boundary, oversized declared dimensions, and pure-garbage fuzz — driving all 5 header-reject reasons and all record-error paths | **217/217 byte-identical** |
| `tests/vectors/pcapng_*` | 226 | valid multi-block/multi-section/multi-interface files in both byte orders; EPB, SPB, and legacy PB packet blocks; IDB timestamp options (`if_tsresol` decimal/binary, `if_tsoffset`, duplicate/wrong-length/out-of-range option rejects); SHB rejects (bad byte-order magic, unsupported version, `BT_SHB_INSANE_MAX` overflow); no-IDB / packet-before-IDB rejects; interface-ID-out-of-range and **caplen>snapshot bounds checks**; second-section IDB linktype/snaplen mismatch; block-length sanity (not-multiple-of-4, too-short, header/trailer mismatch); truncation and single-byte-corruption sweeps; seeded random and pure-garbage fuzz | **226/226 (801 output lines) byte-identical** |

The C references are built by **slicing the parser functions verbatim from the pinned
tarball's `sf-pcap.c` / `sf-pcapng.c`** — `pcap_check_header`, `grow_buffer`, `pcap_next_packet`
for classic-pcap; `read_block`, `get_from_block_data`, `get_opthdr_from_block_data`,
`get_optvalue_from_block_data`, `process_idb_options`, `add_interface`,
`pcap_ng_check_header`, `pcap_ng_cleanup`, `pcap_ng_next_packet` for pcapng — and stitching
them with a minimal shim (the `pcap_t` fields those functions touch, plus a
`tmpfile()`-backed `FILE*` so the upstream `fread` calls run unchanged). See `HARNESS.md`.
`cargo test` replays both envelopes through the crate's `differential_driver` /
`differential_driver_pcapng` and compares against the checked-in goldens;
`scripts/regen_goldens.sh` rebuilds both C references from upstream and re-proves them (CI
runs it every commit).

Because the trace includes the **verbatim error-message text** (e.g. `unsupported pcap
savefile version 2.5`, `savefile linktype reserved field not zero (0x00010000)`, `truncated
dump file; tried to read 16 header bytes, only got 11`), the differential certifies not just
the accept/reject decision but the exact diagnostic each malformed input produces.

## Coverage honesty

Certified (driven by the envelope): the complete `pcap_check_header` + `pcap_next_packet` +
`grow_buffer` logic — magic/byte-order detection, header validation, timestamp scaling, the
length-swap heuristics, and the caplen/snapshot bounds checks and bounded discard path.
Likewise the complete pcapng block-parser logic — SHB/IDB/EPB/SPB/PB block dispatch, option
parsing, per-interface timestamp-resolution tracking and scaling, and the block-length/
caplen/snapshot bounds checks.

Faithfully reduced in the C reference (documented, not silent): the shim's
`linktype_to_dlt` is identity (upstream-faithful for the low-numbered DLTs the envelope uses)
and `max_snaplen_for_dlt` returns `MAXIMUM_SNAPLEN` (what upstream returns for essentially all
DLTs); `pcapint_post_process` is a no-op (it is a no-op for the classic link types the
envelope stays within). These are scaffolding around the verbatim parser, not the parse logic.
The pcapng module additionally does not port multi-DLT `max_blocksize` growth beyond
`INITIAL_MAX_BLOCKSIZE` for exotic link types (the envelope stays within DLTs where upstream's
`MAX_BLOCKSIZE_FOR_SNAPLEN` recompute is a no-op) — out of scope, not silently dropped.

## API shape

A *safe-Rust* port: both parsers read from a byte buffer, return validated packet-header
records, and report errors as Rust errors carrying the upstream diagnostic string. Function
and field names track `sf-pcap.c` / `sf-pcapng.c` so a reader can diff side-by-side. Not
ABI-compatible with C callers.

## Layout

- `src/lib.rs` — the classic-pcap savefile parser (crate root)
- `src/pcapng.rs` — the pcapng block parser (`pub mod pcapng`)
- `src/bin/differential_driver.rs` — classic-pcap certification op-script driver (mirrors `cref/_driver.c`)
- `src/bin/differential_driver_pcapng.rs` — pcapng certification op-script driver (mirrors `cref/_driver_pcapng.c`)
- `cref/` — the C reference harnesses: `_shim.h`/`_shim_pcapng.h` (minimal `pcap_t` + helpers +
  tmpfile `FILE*`), `_driver.c`/`_driver_pcapng.c` (op-script drivers), `assemble.py`/
  `assemble_pcapng.py` (slice the verbatim parsers from an upstream `sf-pcap.c`/`sf-pcapng.c`)
- `tests/differential.rs` + `tests/vectors/` — full envelope replay, both parsers
- `scripts/regen_goldens.sh` — download upstream, build both C references, re-prove both differentials
