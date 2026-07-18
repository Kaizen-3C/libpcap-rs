"""Shared verbatim slice of libpcap 1.10.5's pcapint_post_process cluster and the pseudo-header
structs it dereferences, pinned by line range. Imported by all four assemble scripts
(assemble.py, assemble_pcapng.py, assemble_fuzzlib.py, assemble_fuzzlib_pcapng.py) so the four
C references stay in lockstep instead of carrying four copies of these ranges that could drift.
See cref/_shim.h for why the accessor helpers (SWAPLL, EXTRACT_BE_U_2, DLT_* constants) live in
the shims rather than here. regen_goldens.sh verifies the tarball sha256 before any of this runs.
"""
import io
import os


def _lines(path):
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def _slc(src, a, b):
    return "\n".join(src[a - 1:b])


def postproc_block(G):
    """Return the assembled post-process C block (structs + inline helpers + cluster), verbatim
    from the unpacked upstream tree rooted at G."""
    usb = _lines(os.path.join(G, "pcap", "usb.h"))
    sll = _lines(os.path.join(G, "pcap", "sll.h"))
    nflog = _lines(os.path.join(G, "pcap", "nflog.h"))
    can = _lines(os.path.join(G, "pcap", "can_socketcan.h"))
    pflog = _lines(os.path.join(G, "pflog.h"))
    usbcommon = _lines(os.path.join(G, "pcap-usb-linux-common.h"))
    util = _lines(os.path.join(G, "pcap-util.c"))

    parts = [
        "/*==== pseudo-header structs + constants (VERBATIM from the pcap headers, pflog.h) ====*/",
        _slc(usb, 42, 147),    # URB_* constants, pcap_usb_setup, iso_rec, pcap_usb_header{,_mmapped}, USB_MAXDESC, usb_isodesc
        _slc(sll, 82, 106),    # SLL_HDR_LEN/ADDRLEN, struct sll_header, SLL2_HDR_LEN, struct sll2_header
        _slc(sll, 146, 148),   # LINUX_SLL_P_CAN / CANFD / CANXL
        _slc(nflog, 44, 54),   # nflog_hdr_t, nflog_tlv_t
        _slc(can, 48, 77),     # pcap_can_socketcan_hdr, CANFD_*, pcap_can_socketcan_xl_hdr
        _slc(pflog, 37, 38),   # PFLOG_IFNAMSIZ, PFLOG_RULESET_NAME_SIZE
        _slc(pflog, 123, 154), # struct pfloghdr (Linux branch)
        "/*==== pcap-usb-linux-common.h inline helpers, VERBATIM ====*/",
        _slc(usbcommon, 32, 127),
        "/*==== libpcap 1.10.5 pcap-util.c post-process cluster, VERBATIM ====*/",
        _slc(util, 48, 627),
    ]
    return "\n\n".join(parts)
