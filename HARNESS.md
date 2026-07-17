# The differential harness

How the correctness claim is produced, so it can be verified without trusting this repository.

## The claim

The Rust port and upstream libpcap 1.10.5, driven by the same op-script driver over the
217-case classic-pcap envelope and the 226-case pcapng envelope in `tests/vectors/`, produce
**byte-identical stdout** — including the verbatim upstream diagnostic strings on every
rejection. The two parsers (`sf-pcap.c` / `sf-pcapng.c`) have independent harnesses below;
everything from here through "What the shim faithfully reduces" describes classic-pcap — see
"The pcapng harness" further down for what differs.

## How the C reference is built (`scripts/regen_goldens.sh`)

1. Download `libpcap-1.10.5.tar.gz` from tcpdump.org and verify sha256
   `37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0`.
2. `cref/assemble.py` slices the **verbatim** function bodies from the upstream `src/sf-pcap.c`
   by pinned line range: the `pcap_sf_pkthdr` / `pcap_sf_patched_pkthdr` structs, the
   `swapped_type_t` / `tstamp_scale_type_t` enums and `struct pcap_sf`, and the three parser
   functions `pcap_check_header`, `grow_buffer`, and `pcap_next_packet`.
3. It prepends `cref/_shim.h` — the minimal `pcap_t` (only the fields those functions touch),
   the constants/macros they reference from `pcap-int.h` / `pcap/pcap.h`, small helper
   definitions (`pcapint_open_offline_common`, `pcapint_adjust_snapshot`, `linktype_to_dlt`,
   `max_snaplen_for_dlt`, `pcapint_fmt_errmsg_for_errno`, `pcapint_sf_cleanup`,
   `pcapint_post_process`), and nothing that alters the parse logic — and appends
   `cref/_driver.c`, the op-script driver. **The shim is the only added code; the parser
   bodies are verbatim upstream.**
4. The driver backs a real `FILE*` with a `tmpfile()` (so the verbatim `fread` calls run
   unchanged), replays the exact caller sequence libpcap uses — read the 4-byte magic, call
   `pcap_check_header`, set `p->rfile`, loop `p->next_packet_op` — and prints the trace.
5. Compile and run over `tests/vectors/pcap_inputs.txt`; byte-compare the C output against the
   Rust `differential_driver` and the checked-in golden.

CI runs this on every commit, so "byte-identical to upstream" is re-proven from libpcap's own
code, not taken on faith.

## The op-script format

Each stdin line is one hex-encoded classic-pcap file. The driver parses it and prints:

- `H <vmaj> <vmin> <swapped> <linktype> <snapshot>` — file header accepted
- `X <errbuf>` — header rejected, with libpcap's verbatim diagnostic (or `not-pcap` when the
  magic doesn't match and upstream sets no message)
- `P <caplen> <len> <sec> <usec> <fnv>` — packet accepted: header fields + FNV-1a of the
  captured bytes
- `E <errbuf>` — packet rejected, with libpcap's verbatim diagnostic
- `Z <n>` — clean EOF after n packets

Every line ends with a `.` separator. Full op semantics are documented at the top of
`cref/_driver.c`.

## What the shim faithfully reduces (documented, not silent)

The three sliced functions call out to a few libpcap helpers that live in other TUs
(`pcap-common.c`, `pcap-util.c`). The shim provides upstream-faithful behavior for the
classic-pcap path the envelope exercises: `linktype_to_dlt` is identity (correct for the
low-numbered DLTs used), `max_snaplen_for_dlt` returns `MAXIMUM_SNAPLEN` (upstream's value for
essentially every DLT), and `pcapint_post_process` is a no-op (it is a no-op for the classic
link types the envelope stays within). These surround the verbatim parser; they are not the
parse/validation/bounds-check logic, which is sliced unchanged.

## Regenerating or extending the envelope

The input vectors are plain text (one hex `.pcap` per line). Add lines and rerun
`scripts/regen_goldens.sh` — it rebuilds goldens from the upstream C, so the reference is
always libpcap's code, never this port.

## The pcapng harness

Same methodology, `cref/assemble_pcapng.py` slices from `src/sf-pcapng.c` instead: the
block-type structs (`block_header`/`block_trailer`/`option_header`/`section_header_block`/
`interface_description_block`/`enhanced_packet_block`/`simple_packet_block`/`packet_block`/
`block_cursor`), the per-interface/per-`pcap_t` private state, and nine functions —
`read_bytes`, `read_block`, `get_from_block_data`, `get_opthdr_from_block_data`,
`get_optvalue_from_block_data`, `process_idb_options`, `add_interface`,
`pcap_ng_check_header`, `pcap_ng_cleanup`, `pcap_ng_next_packet` — by pinned line range against
libpcap 1.10.5. `cref/_shim_pcapng.h` supplies the same class of scaffolding as the classic
shim (reduced `pcap_t`, `PCAP_OPEN_OFFLINE_COMMON`, `pcapint_adjust_snapshot`,
`linktype_to_dlt`, `max_snaplen_for_dlt`, `pcapint_fmt_errmsg_for_errno`,
`pcapint_sf_cleanup`, `pcapint_post_process`, `SWAPLONG`/`SWAPSHORT`/`SWAPLL`) plus the same
tmpfile-backed `FILE*`. `cref/_driver_pcapng.c` replays the caller sequence
(`pcap_ng_check_header`, then loop `p->next_packet_op`) and prints the same trace grammar as
the classic driver (`H`/`X`/`P`/`E`/`Z`), except `X` disambiguates "not pcapng" (magic/BOM
mismatch, or a too-short read before either is checked — `err == 0` in upstream's own
`*err` out-parameter) from a real parse error (`err == 1`) exactly as `pcap_ng_check_header`
itself does — both cases already surface the right string, so the driver does not need to
track `*err` separately. Not ported (documented, not silent): the `MAX_BLOCKSIZE_FOR_SNAPLEN`
regrowth of `max_blocksize` after the first IDB is found — a no-op under the shim's
`max_snaplen_for_dlt` stub since `INITIAL_MAX_BLOCKSIZE` (16 MiB) already exceeds it for every
DLT the envelope uses, so dropping it doesn't change observable behavior here.

Multi-generation-size note: `sf-pcapng.c`'s parser surface (~1,260 verbatim lines across
structs + 9 functions) is over the pipeline's reliable single-generation ceiling
(~600–800 output lines; see the libtiff Run I/J precedent). Unlike the multi-codec libtiff
case, this port converged as a **single translate run** without needing a manual per-function
split — the ladder needed all three rungs (haiku and sonnet plateaued around 355–397/226
differ; opus converged first attempt) but produced one coherent 932-line file, not several
modules composed after the fact.
