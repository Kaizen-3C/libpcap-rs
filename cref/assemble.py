"""Assemble the self-contained C reference `legacy.c` for the libpcap savefile-parser
differential: the shim (_shim.h) + VERBATIM function bodies sliced from the upstream libpcap
1.10.5 src/sf-pcap.c + the post-processing cluster sliced verbatim from pcap-util.c (and the
pseudo-header structs it needs, sliced verbatim from the pcap/*.h headers) + the op-script
driver (_driver.c).

Usage:  PCAP_SRC=<unpacked libpcap-1.10.5 dir> OUT=<build dir> python cref/assemble.py
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


sf = lines(os.path.join(G, "sf-pcap.c"))

# --- pseudo-header structs + constants the post-process cluster dereferences, sliced verbatim
#     from the upstream headers (pinned to 1.10.5). These are the byte-exact layouts that
#     swap_pseudo_headers/pcapint_post_process reach into via offsetof, so they MUST come from
#     the tarball, not be transcribed. ---
usb = lines(os.path.join(G, "pcap", "usb.h"))
sll = lines(os.path.join(G, "pcap", "sll.h"))
nflog = lines(os.path.join(G, "pcap", "nflog.h"))
can = lines(os.path.join(G, "pcap", "can_socketcan.h"))
pflog = lines(os.path.join(G, "pflog.h"))
usbcommon = lines(os.path.join(G, "pcap-usb-linux-common.h"))
util = lines(os.path.join(G, "pcap-util.c"))

pseudo_structs = [
    "/*==== pseudo-header structs + constants (VERBATIM from the pcap headers, pflog.h) ====*/",
    slc(usb, 42, 147),    # URB_* constants, pcap_usb_setup, iso_rec, pcap_usb_header{,_mmapped}, USB_MAXDESC, usb_isodesc
    slc(sll, 82, 106),    # SLL_HDR_LEN/ADDRLEN, struct sll_header, SLL2_HDR_LEN, struct sll2_header
    slc(sll, 146, 148),   # LINUX_SLL_P_CAN / CANFD / CANXL
    slc(nflog, 44, 54),   # nflog_hdr_t, nflog_tlv_t
    slc(can, 48, 77),     # pcap_can_socketcan_hdr, CANFD_*, pcap_can_socketcan_xl_hdr
    slc(pflog, 37, 38),   # PFLOG_IFNAMSIZ, PFLOG_RULESET_NAME_SIZE
    slc(pflog, 123, 154), # struct pfloghdr (Linux #else branch compiles; OpenBSD pf_addr fields elided)
]

# usb-linux-common inline helpers (is_isochronous_transfer_completion, iso_pseudo_header_len,
# incoming_isochronous_transfer_completed_len) the USB length fixup in pcapint_post_process calls.
usb_common_inlines = [
    "/*==== pcap-usb-linux-common.h inline helpers, VERBATIM ====*/",
    slc(usbcommon, 32, 127),
]

# the post-process cluster itself: swap_pflog_header, swap_socketcan_header,
# swap_linux_sll{,2}_socketcan_header, swap_linux_usb_header, swap_nflog_header,
# swap_pseudo_headers, packet_length_might_be_wrong, pcapint_post_process.
postproc_cluster = [
    "/*==== libpcap 1.10.5 pcap-util.c post-process cluster, VERBATIM ====*/",
    slc(util, 48, 627),
]

verbatim = [
    slc(sf, 152, 156),   # struct pcap_sf_pkthdr
    slc(sf, 168, 175),   # struct pcap_sf_patched_pkthdr
    slc(sf, 196, 212),   # swapped_type_t + tstamp_scale_type_t + struct pcap_sf
    slc(sf, 218, 492),   # pcap_check_header
    slc(sf, 497, 510),   # grow_buffer
    slc(sf, 517, 789),   # pcap_next_packet (calls pcapint_post_process at the tail)
]

shim = io.open(os.path.join(HERE, "_shim.h"), encoding="utf-8").read()
driver = io.open(os.path.join(HERE, "_driver.c"), encoding="utf-8").read()

out = [shim,
       "\n\n".join(pseudo_structs),
       "\n\n".join(usb_common_inlines),
       "\n\n".join(postproc_cluster),
       "/*==== libpcap 1.10.5 src/sf-pcap.c savefile parser, VERBATIM ====*/",
       "\n\n".join(verbatim),
       driver]
with io.open(os.path.join(OUT, "legacy.c"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n\n".join(out) + "\n")
print("legacy.c assembled: sf-pcap.c parser + pcap-util.c post-process cluster (verbatim) + shim + driver")
