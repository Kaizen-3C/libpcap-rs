# The differential harness

How the correctness claim is produced, so it can be verified without trusting this repository.

## The claim

The Rust port and upstream libpcap 1.10.5, driven by the same op-script driver over the
217-case envelope in `tests/vectors/`, produce **byte-identical stdout** — including the
verbatim upstream diagnostic strings on every rejection.

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
