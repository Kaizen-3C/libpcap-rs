# libpcap-rs

A memory-safe Rust port of the **libpcap 1.10.5** classic-pcap *savefile parser* — the
untrusted-input path from `src/sf-pcap.c`: `pcap_check_header` (file-header validation, byte-
order detection, version/linktype/reserved-field checks) and `pcap_next_packet` (per-record
parsing, timestamp scaling, caplen/len swap heuristics, and the **caplen/snapshot bounds
checks that are libpcap's historical CVE surface**).

The entire crate is **`#![forbid(unsafe_code)]`** and has **zero dependencies**.

## Provenance

- Ported from `libpcap-1.10.5.tar.gz`, sha256
  `37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0` (tcpdump.org).
- Licensed BSD-3-Clause, identical to upstream; see `LICENSE` (libpcap's, UC Regents /
  tcpdump.org copyright retained).

## Scope

This is the **classic-pcap savefile reader**, not all of libpcap. In scope: the file-header
and packet-record parser that turns untrusted `.pcap` bytes into validated packet headers +
captured data. Out of scope (and not ported): live capture (OS syscalls, BPF), the pcapng
format (`sf-pcapng.c`), the full DLT/linktype-to-DLT mapping table, and the encoder/dumper.
The parser is the security-relevant subset — it's what runs first on a hostile file.

## Certification methodology

This port was not reviewed into correctness — it was **measured** into it. The upstream C
parser and the Rust port are both driven by an identical op-script harness (one hex-encoded
`.pcap` file per stdin line) over a declared envelope, and their complete observable stdout —
parsed header fields, per-packet caplen/len/timestamp/data-hash, **and the verbatim upstream
diagnostic strings on every rejection** — is byte-compared against the upstream C build:

| Envelope | Cases | What it exercises | Result |
|---|---|---|---|
| `tests/vectors/pcap_*` | 217 | valid files across all versions (2.0–2.4, 543.0), link types, little/big-endian, and the three magic variants (standard, nanosecond, Kuznetzov-patched-header); snaplen edges (0→clamp, 1, MAXIMUM_SNAPLEN, over); caplen/len swap heuristics; **the caplen>max and caplen>snapshot bounds checks** (fired 75× across the corpus); **plus** an adversarial half — bad magic, single-byte corruption at every header offset, truncation at every field boundary, oversized declared dimensions, and pure-garbage fuzz — driving all 5 header-reject reasons and all record-error paths | **217/217 byte-identical** |

The C reference is built by **slicing `pcap_check_header`, `grow_buffer`, and
`pcap_next_packet` verbatim from the pinned tarball's `sf-pcap.c`** and stitching them with a
minimal shim (the `pcap_t` fields those functions touch, plus a `tmpfile()`-backed `FILE*` so
the upstream `fread` calls run unchanged). See `HARNESS.md`. `cargo test` replays the envelope
through the crate's `differential_driver` and compares against the checked-in golden;
`scripts/regen_goldens.sh` rebuilds the C reference from upstream and re-proves it (CI runs it
every commit).

Because the trace includes the **verbatim error-message text** (e.g. `unsupported pcap
savefile version 2.5`, `savefile linktype reserved field not zero (0x00010000)`, `truncated
dump file; tried to read 16 header bytes, only got 11`), the differential certifies not just
the accept/reject decision but the exact diagnostic each malformed input produces.

## Coverage honesty

Certified (driven by the envelope): the complete `pcap_check_header` + `pcap_next_packet` +
`grow_buffer` logic — magic/byte-order detection, header validation, timestamp scaling, the
length-swap heuristics, and the caplen/snapshot bounds checks and bounded discard path.

Faithfully reduced in the C reference (documented, not silent): the shim's
`linktype_to_dlt` is identity (upstream-faithful for the low-numbered DLTs the envelope uses)
and `max_snaplen_for_dlt` returns `MAXIMUM_SNAPLEN` (what upstream returns for essentially all
DLTs); `pcapint_post_process` is a no-op (it is a no-op for the classic link types the
envelope stays within). These are scaffolding around the verbatim parser, not the parse logic.

## API shape

A *safe-Rust* port: the parser reads from a byte buffer, returns validated `PcapPktHdr`
records, and reports errors as Rust errors carrying the upstream diagnostic string. Function
and field names track `sf-pcap.c` so a reader can diff side-by-side. Not ABI-compatible with C
callers.

## Layout

- `src/lib.rs` — the savefile parser
- `src/bin/differential_driver.rs` — the certification op-script driver (mirrors `cref/_driver.c`)
- `cref/` — the C reference harness: `_shim.h` (minimal `pcap_t` + helpers + tmpfile `FILE*`),
  `_driver.c` (op-script driver), `assemble.py` (slices the verbatim parser from an upstream
  `sf-pcap.c`)
- `tests/differential.rs` + `tests/vectors/` — full envelope replay
- `scripts/regen_goldens.sh` — download upstream, build the C reference, re-prove the differential
