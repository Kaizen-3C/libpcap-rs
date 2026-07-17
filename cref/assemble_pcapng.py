"""Assemble the self-contained C reference `legacy_pcapng.c` for the libpcap pcapng
block-parser differential: the shim (_shim_pcapng.h) + VERBATIM function bodies sliced from
the upstream libpcap 1.10.5 src/sf-pcapng.c + the op-script driver (_driver_pcapng.c).

Usage:  PCAP_SRC=<unpacked libpcap-1.10.5 dir> OUT=<build dir> python cref/assemble_pcapng.py
The verbatim line ranges below are pinned to libpcap 1.10.5; regen_goldens.sh verifies the
tarball sha256 before calling this.
"""
import io
import os

G = os.environ["PCAP_SRC"]
OUT = os.environ.get("OUT", ".")
HERE = os.path.dirname(os.path.abspath(__file__))


def lines(path):
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def slc(src, a, b):
    return "\n".join(src[a - 1:b])


sf = lines(os.path.join(G, "sf-pcapng.c"))

verbatim = [
    slc(sf, 45, 253),     # block-type structs, per-interface/per-pcap_t state, fwd decls
    slc(sf, 255, 276),    # read_bytes
    slc(sf, 278, 385),    # read_block
    slc(sf, 387, 411),    # get_from_block_data
    slc(sf, 413, 435),    # get_opthdr_from_block_data
    slc(sf, 437, 457),    # get_optvalue_from_block_data
    slc(sf, 459, 588),    # process_idb_options
    slc(sf, 590, 761),    # add_interface
    slc(sf, 763, 1083),   # pcap_ng_check_header
    slc(sf, 1085, 1092),  # pcap_ng_cleanup
    slc(sf, 1094, 1516),  # pcap_ng_next_packet
]

shim = io.open(os.path.join(HERE, "_shim_pcapng.h"), encoding="utf-8").read()
driver = io.open(os.path.join(HERE, "_driver_pcapng.c"), encoding="utf-8").read()

out = [shim,
       "/*==== libpcap 1.10.5 src/sf-pcapng.c pcapng block parser, VERBATIM ====*/",
       "\n\n".join(verbatim),
       driver]
with io.open(os.path.join(OUT, "legacy_pcapng.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(out) + "\n")
print("legacy_pcapng.c assembled from libpcap 1.10.5 sf-pcapng.c (verbatim parser + shim + driver)")
