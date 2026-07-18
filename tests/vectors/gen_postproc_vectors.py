"""Generate classic-pcap differential vectors that exercise pcapint_post_process's per-DLT
pseudo-header byte-swaps and the DLT_USB_LINUX_MMAPPED isochronous original-length fixup
(libpcap#1702). Emits one hex-encoded pcap file per line, to be appended to pcap_inputs.txt;
regen_goldens.sh then re-derives the golden from the upstream C reference and byte-compares the
Rust port against it, so any divergence in the hand-port surfaces here.

Each vector is built to reach a specific branch: the swaps only run on a byte-swapped file
(magic 0xa1b2c3d4 stored big-endian, all header/record integers big-endian), and the USB
isochronous fixup runs on either byte order but needs a precise pseudo-header shape. The
pseudo-header field bytes are arbitrary patterns — the differential only cares that C and Rust
transform them identically.
"""
import struct

# pcap/dlt.h link types the cluster handles.
DLT_LINUX_SLL = 113
DLT_PFLOG = 117
DLT_USB_LINUX = 189
DLT_USB_LINUX_MMAPPED = 220
DLT_NFLOG = 239
DLT_LINUX_SLL2 = 276


def pcap_file(linktype, packets, swapped):
    """packets: list of (caplen, length, payload_bytes)."""
    if swapped:
        e = ">"
        magic = b"\xa1\xb2\xc3\xd4"  # -> magic_int 0xd4c3b2a1 on an LE host => swapped
    else:
        e = "<"
        magic = b"\xd4\xc3\xb2\xa1"  # -> magic_int 0xa1b2c3d4 on an LE host => not swapped
    out = magic + struct.pack(e + "HHiIII", 2, 4, 0, 0, 262144, linktype)
    for caplen, length, payload in packets:
        out += struct.pack(e + "IIII", 0, 0, caplen, length) + payload
    return out


def pat(n, start=0):
    """n distinct bytes (a recognizable pattern so a wrong/skipped swap is visible)."""
    return bytes((start + i) & 0xff for i in range(n))


vectors = []


def add(name, linktype, packets, swapped):
    blob = pcap_file(linktype, packets, swapped)
    vectors.append((name, blob.hex()))


# --- PFLOG: swap uid/pid/rule_uid/rule_pid (offsets 44/48/52/56); pfloghdr length byte @0 gates
#     how many get swapped. Full (length=64) swaps all four; a short length stops early. ---
pflog_full = bytearray(pat(64))
pflog_full[0] = 64  # pfloghdr_length -> all four fields in range
add("pflog_swapped_full", DLT_PFLOG, [(64, 64, bytes(pflog_full))], swapped=True)

pflog_short = bytearray(pat(64))
pflog_short[0] = 50  # pfloghdr_length < offsetof(pid)+4 -> only uid swapped
add("pflog_swapped_shorthdr", DLT_PFLOG, [(64, 64, bytes(pflog_short))], swapped=True)

# caplen just short of the pid field -> uid swapped, then guard returns
add("pflog_swapped_truncated", DLT_PFLOG, [(50, 50, bytes(pflog_full)[:50])], swapped=True)

# --- SLL + SocketCAN: sll_protocol @14 (big-endian) selects CAN / CAN-FD / CAN-XL; the CAN
#     header sits right after the 16-byte SLL header. ---
def sll_can(proto_be, canhdr):
    b = bytearray(16 + len(canhdr))
    b[0:14] = pat(14)
    b[14] = (proto_be >> 8) & 0xff
    b[15] = proto_be & 0xff
    b[16:] = canhdr
    return bytes(b)


add("sll_can_swapped", DLT_LINUX_SLL, [(20, 20, sll_can(0x000C, pat(4, 0x10)))], swapped=True)
add("sll_canfd_swapped", DLT_LINUX_SLL, [(20, 20, sll_can(0x000D, pat(4, 0x20)))], swapped=True)
# CAN-XL needs 12 bytes of header (priority_vcid, payload_length @6, acceptance_field @8)
add("sll_canxl_swapped", DLT_LINUX_SLL, [(28, 28, sll_can(0x000E, pat(12, 0x30)))], swapped=True)
# non-CAN protocol -> swap_socketcan_header does nothing (still valid, identity on the payload)
add("sll_noncan_swapped", DLT_LINUX_SLL, [(20, 20, sll_can(0x0800, pat(4, 0x40)))], swapped=True)


def sll2_can(proto_be, canhdr):
    b = bytearray(20 + len(canhdr))
    b[0] = (proto_be >> 8) & 0xff  # sll2_protocol @0
    b[1] = proto_be & 0xff
    b[2:20] = pat(18, 2)
    b[20:] = canhdr
    return bytes(b)


add("sll2_can_swapped", DLT_LINUX_SLL2, [(24, 24, sll2_can(0x000C, pat(4, 0x50)))], swapped=True)

# --- USB linux (48-byte header) and mmapped (64-byte) ---
def usb_hdr(transfer_type, mmapped, ndesc=0, extra=b""):
    n = 64 if mmapped else 48
    b = bytearray(pat(n))
    b[8] = 0x43  # event_type 'C'
    b[9] = transfer_type
    b[10] = 0x81  # endpoint_number (URB_TRANSFER_IN set)
    b[15] = 0  # data_flag = 0
    if mmapped:
        # ndesc @60, stored big-endian for a swapped file so the swap yields ndesc on read
        b[60:64] = struct.pack(">I", ndesc)
    return bytes(b) + extra


# USB_LINUX, bulk (non-isochronous) -> skips the setup header
add("usb_linux_bulk_swapped", DLT_USB_LINUX, [(48, 48, usb_hdr(0x03, False))], swapped=True)
# USB_LINUX, isochronous -> swaps s.iso.error_count / numdesc
add("usb_linux_iso_swapped", DLT_USB_LINUX, [(48, 48, usb_hdr(0x00, False))], swapped=True)

# USB_MMAPPED isochronous with 2 descriptors (swapped) -> swaps ndesc then each descriptor
descs = pat(32, 0x60)
add(
    "usb_mmapped_iso_swapped",
    DLT_USB_LINUX_MMAPPED,
    [(96, 96, usb_hdr(0x00, True, ndesc=2, extra=descs))],
    swapped=True,
)

# --- NFLOG: fixed 4-byte header (version @1 must be 0), then TLVs whose length/type are swapped ---
def nflog(tlvs, swapped):
    e = ">" if swapped else "<"
    b = bytearray(4)
    b[0] = 2  # family
    b[1] = 0  # version 0
    b[2:4] = pat(2, 0x70)  # rid
    for length, typ, val in tlvs:
        b += struct.pack(e + "HH", length, typ) + val
    return bytes(b)


# one TLV, length 4 (just the header, 4-aligned)
add("nflog_swapped_1tlv", DLT_NFLOG, [(8, 8, nflog([(4, 0x0001, b"")], True))], swapped=True)
# two TLVs, second with a 4-byte value (length 8)
add(
    "nflog_swapped_2tlv",
    DLT_NFLOG,
    [(16, 16, nflog([(4, 0x0001, b""), (8, 0x0002, pat(4, 0x80))], True))],
    swapped=True,
)

# --- USB_MMAPPED isochronous original-length FIXUP (unswapped), the fiddly case. ---
def usb_mmapped_fixup(ndesc, urb_len, descriptors, event='C', transfer=0x00,
                      endpoint=0x81, data_flag=0):
    b = bytearray(pat(64))
    b[8] = ord(event)
    b[9] = transfer
    b[10] = endpoint
    b[15] = data_flag
    b[32:36] = struct.pack("<I", urb_len)  # urb_len (unswapped -> LE)
    b[60:64] = struct.pack("<I", ndesc)
    return bytes(b) + descriptors


# 1 descriptor: offset=10, len=40 -> desc_end 50; iso_pseudo_header_len(1)=80; new len = 130.
# Record len set to old_style = 80 + urb_len(100) = 180 so packet_length_might_be_wrong() is true.
desc1 = struct.pack("<III", 0, 10, 40) + b"\x00\x00\x00\x00"  # status, offset, len, pad
add(
    "usb_mmapped_fixup_trigger",
    DLT_USB_LINUX_MMAPPED,
    [(80, 180, usb_mmapped_fixup(1, 100, desc1))],
    swapped=False,
)
# Same shape but record len != old_style -> fixup does NOT fire (len stays as given).
add(
    "usb_mmapped_fixup_notrigger",
    DLT_USB_LINUX_MMAPPED,
    [(80, 999, usb_mmapped_fixup(1, 100, desc1))],
    swapped=False,
)
# ndesc > USB_MAXDESC -> bail out before the fixup.
add(
    "usb_mmapped_fixup_ndesc_insane",
    DLT_USB_LINUX_MMAPPED,
    [(80, 180, usb_mmapped_fixup(200, 100, desc1))],
    swapped=False,
)
# data present but not an isochronous-completion (bulk) -> no fixup.
add(
    "usb_mmapped_fixup_notiso",
    DLT_USB_LINUX_MMAPPED,
    [(80, 180, usb_mmapped_fixup(1, 100, desc1, transfer=0x03))],
    swapped=False,
)

# --- Unswapped exotic DLTs: post_process is identity (except the USB fixup above) — sanity. ---
add("pflog_unswapped_identity", DLT_PFLOG, [(64, 64, bytes(pflog_full))], swapped=False)
add("nflog_unswapped_identity", DLT_NFLOG, [(8, 8, nflog([(4, 0x0001, b"")], False))], swapped=False)


# --- pcapng vectors: exercise the pcap_ng_next_packet call site (same post_process function).
#     A minimal section: SHB + IDB(linktype) + one EPB carrying the pseudo-header. ---
def _pad4(b):
    return b + b"\x00" * ((4 - len(b) % 4) % 4)


def pcapng_file(linktype, caplen, length, payload, swapped):
    e = ">" if swapped else "<"

    def block(btype, body):
        total = 12 + len(body)
        return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)

    # SHB: byte_order_magic 0x1A2B3C4D (its stored byte order tells the reader the section's
    # endianness), version 1.0, section_length -1. block_type 0x0A0D0D0A is a byte-palindrome.
    shb_body = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = block(0x0A0D0D0A, shb_body)
    # IDB: linktype (u16), reserved (u16), snaplen (u32)
    idb = block(0x00000001, struct.pack(e + "HHI", linktype, 0, 262144))
    # EPB: interface_id, ts_high, ts_low, caplen, len, padded packet data
    epb_body = struct.pack(e + "IIIII", 0, 0, 0, caplen, length) + _pad4(payload)
    epb = block(0x00000006, epb_body)
    return shb + idb + epb


pcapng_vectors = []


def addng(name, linktype, caplen, length, payload, swapped):
    blob = pcapng_file(linktype, caplen, length, payload, swapped)
    pcapng_vectors.append((name, blob.hex()))


# USB mmapped isochronous fixup (unswapped) — the len-changing case, through the pcapng path.
addng("ng_usb_mmapped_fixup_trigger", DLT_USB_LINUX_MMAPPED, 80, 180,
      usb_mmapped_fixup(1, 100, desc1), swapped=False)
# USB mmapped isochronous, byte-swapped section — exercises the swap through the pcapng path.
addng("ng_usb_mmapped_iso_swapped", DLT_USB_LINUX_MMAPPED, 96, 96,
      usb_hdr(0x00, True, ndesc=2, extra=pat(32, 0x60)), swapped=True)
# PFLOG swapped through the pcapng path.
addng("ng_pflog_swapped_full", DLT_PFLOG, 64, 64, bytes(pflog_full), swapped=True)


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "pcap"
    if mode == "pcapng":
        for name, hexline in pcapng_vectors:
            print(hexline)
        for name, _ in pcapng_vectors:
            print(name, file=sys.stderr)
    else:
        for name, hexline in vectors:
            print(hexline)
        for name, _ in vectors:
            print(name, file=sys.stderr)
