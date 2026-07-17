"""Assemble `legacy_fuzzlib.c`: the shim (_shim.h) + VERBATIM function bodies sliced from
upstream libpcap 1.10.5 src/sf-pcap.c (identical slice to assemble.py) + an in-process callable
wrapper (_fuzzlib_driver.c) instead of the op-script main() in _driver.c. Used by the
differential-fuzz build (fuzz/build.rs) so the fuzz oracle is built from the same verbatim slice
as the certified `differential_driver`.

Usage:  PCAP_SRC=<unpacked libpcap-1.10.5 dir> OUT=<build dir> python cref/assemble_fuzzlib.py
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


sf = lines(os.path.join(G, "sf-pcap.c"))

verbatim = [
    slc(sf, 152, 156),   # struct pcap_sf_pkthdr
    slc(sf, 168, 175),   # struct pcap_sf_patched_pkthdr
    slc(sf, 196, 212),   # swapped_type_t + tstamp_scale_type_t + struct pcap_sf
    slc(sf, 218, 492),   # pcap_check_header
    slc(sf, 497, 510),   # grow_buffer
    slc(sf, 517, 789),   # pcap_next_packet
]

shim = io.open(os.path.join(HERE, "_shim.h"), encoding="utf-8").read()
driver = io.open(os.path.join(HERE, "_fuzzlib_driver.c"), encoding="utf-8").read()

out = [shim,
       "/*==== libpcap 1.10.5 src/sf-pcap.c savefile parser, VERBATIM ====*/",
       "\n\n".join(verbatim),
       driver]
with io.open(os.path.join(OUT, "legacy_fuzzlib.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(out) + "\n")
print("legacy_fuzzlib.c assembled from libpcap 1.10.5 sf-pcap.c (verbatim parser + shim + fuzz wrapper)")
