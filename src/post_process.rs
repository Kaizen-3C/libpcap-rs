//! Port of libpcap 1.10.5 `pcap-util.c`'s `pcapint_post_process` and its per-DLT
//! pseudo-header byte-swap helpers (`swap_pseudo_headers`, `swap_pflog_header`,
//! `swap_socketcan_header`, `swap_linux_sll{,2}_socketcan_header`, `swap_linux_usb_header`,
//! `swap_nflog_header`) plus the `DLT_USB_LINUX_MMAPPED` isochronous original-length fixup
//! (`packet_length_might_be_wrong` + `pcap-usb-linux-common.h`'s
//! `incoming_isochronous_transfer_completed_len`). This is the tail step of the C
//! `pcap_next_packet`/`pcap_ng_next_packet` that the classic + pcapng ports were missing
//! (libpcap#1702); `post_process` is called from both after a packet's bytes are in the buffer.
//!
//! The C code casts the packet buffer to the pseudo-header structs and byte-swaps fields in
//! place; `#![forbid(unsafe_code)]` can't do that cast, so every access is by the exact byte
//! offset of the field in the upstream struct layout (checked against the C headers), and a field
//! swap is a reversal of the field's bytes — the buffer-level effect of the C's `SWAP*`.
//!
//! Endianness (fixed after libpcap#1702; thanks to G. Harris): the pseudo-headers are captured in
//! the *writing* host's byte order and must be delivered in the *reading* host's byte order, so the
//! swap is needed iff those differ — which is exactly what libpcap's host-relative `swapped` flag
//! means. `pcap_check_header` now stores that host-relative flag (see there), so `post_process`
//! gates on `swapped` directly. Every subsequent field read is of a value already in reading-host
//! order, so it uses native-endian helpers (`rd_u*_host`) rather than assuming little-endian. On a
//! little-endian host all of this reduces to the previous behaviour, so the byte-identical
//! differential is unchanged; on a big-endian host it now matches upstream. The harness observes
//! both effects (the driver FNV-hashes the post-processed bytes and prints `len`) and is cross-run
//! as a verbatim-C-vs-Rust differential under qemu-s390x, so the big-endian path is exercised.

// DLT values handled here (verbatim from pcap/dlt.h).
const DLT_PFLOG: u32 = 117;
const DLT_LINUX_SLL: u32 = 113;
const DLT_LINUX_SLL2: u32 = 276;
const DLT_USB_LINUX: u32 = 189;
const DLT_USB_LINUX_MMAPPED: u32 = 220;
const DLT_NFLOG: u32 = 239;

// SLL/SLL2 fake link-layer header sizes (pcap/sll.h).
const SLL_HDR_LEN: usize = 16;
const SLL2_HDR_LEN: usize = 20;
// SocketCAN protocol types carried in the SLL protocol field (pcap/sll.h).
const LINUX_SLL_P_CAN: u16 = 0x000C;
const LINUX_SLL_P_CANFD: u16 = 0x000D;
const LINUX_SLL_P_CANXL: u16 = 0x000E;

// USB (pcap/usb.h): memory-mapped pseudo-header + isochronous descriptor sizes and URB flags.
const USB_MMAPPED_HDR_LEN: u32 = 64;
const USB_ISODESC_LEN: u32 = 16;
const USB_MAXDESC: u32 = 128;
const URB_TRANSFER_IN: u8 = 0x80;
const URB_ISOCHRONOUS: u8 = 0x0;
const URB_COMPLETE: u8 = b'C';

// nflog fixed header + TLV header sizes (pcap/nflog.h).
const NFLOG_HDR_LEN: u32 = 4;
const NFLOG_TLV_LEN: u32 = 4;

/// Reverse `n` bytes at `off` — the buffer-level effect of C's `field = SWAP*(field)`.
fn swap_bytes(data: &mut [u8], off: usize, n: usize) {
    if off + n <= data.len() {
        data[off..off + n].reverse();
    }
}

/// Read a pseudo-header field that is in READING-HOST byte order at this point — either the file's
/// byte order already matched the host, or `swap_pseudo_headers` byte-reversed the field into host
/// order. Uses native endianness, so the value is correct on both little- and big-endian hosts; on
/// the little-endian check host this is byte-for-byte identical to a `from_le_bytes` read.
fn rd_u16_host(data: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([data[off], data[off + 1]])
}

fn rd_u32_host(data: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// `EXTRACT_BE_U_2`: big-endian 2-byte read (the SLL protocol field is big-endian).
fn extract_be_u2(data: &[u8], off: usize) -> u16 {
    ((data[off] as u16) << 8) | (data[off + 1] as u16)
}

/// `u_int_sum`: add, clamping to `UINT_MAX`.
fn u_int_sum(a: u32, b: u32) -> u32 {
    a.saturating_add(b)
}

// --- swap_pflog_header: uid/pid/rule_uid/rule_pid are host-order in the pflog pseudo-header ---
fn swap_pflog_header(caplen: u32, length: u32, data: &mut [u8]) {
    // offsetof into struct pfloghdr (pflog.h, Linux layout): uid=44, pid=48, rule_uid=52,
    // rule_pid=56; length (pfloghdr_length) is the first byte.
    if caplen < 48 || length < 48 {
        return;
    }
    let pfloghdr_length = data[0] as u32;
    if pfloghdr_length < 48 {
        return;
    }
    swap_bytes(data, 44, 4); // uid

    if caplen < 52 || length < 52 {
        return;
    }
    if pfloghdr_length < 52 {
        return;
    }
    swap_bytes(data, 48, 4); // pid

    if caplen < 56 || length < 56 {
        return;
    }
    if pfloghdr_length < 56 {
        return;
    }
    swap_bytes(data, 52, 4); // rule_uid

    if caplen < 60 || length < 60 {
        return;
    }
    if pfloghdr_length < 60 {
        return;
    }
    swap_bytes(data, 56, 4); // rule_pid
}

// --- swap_socketcan_header: byte-swap the CAN/CAN-FD/CAN-XL header at `base` in `data` ---
fn swap_socketcan_header(protocol: u16, caplen: u32, length: u32, data: &mut [u8], base: usize) {
    match protocol {
        LINUX_SLL_P_CAN | LINUX_SLL_P_CANFD => {
            // pcap_can_socketcan_hdr: can_id at offset 0.
            if caplen < 4 || length < 4 {
                return;
            }
            swap_bytes(data, base, 4); // can_id
        }
        LINUX_SLL_P_CANXL => {
            // pcap_can_socketcan_xl_hdr: priority_vcid@0, payload_length@6, acceptance_field@8.
            if caplen < 4 || length < 4 {
                return;
            }
            swap_bytes(data, base, 4); // priority_vcid
            if caplen < 8 || length < 8 {
                return;
            }
            swap_bytes(data, base + 6, 2); // payload_length
            if caplen < 12 || length < 12 {
                return;
            }
            swap_bytes(data, base + 8, 4); // acceptance_field
        }
        _ => {}
    }
}

fn swap_linux_sll_socketcan_header(caplen: u32, length: u32, data: &mut [u8]) {
    if caplen < SLL_HDR_LEN as u32 || length < SLL_HDR_LEN as u32 {
        return;
    }
    let protocol = extract_be_u2(data, 14); // sll_header.sll_protocol @14
    swap_socketcan_header(
        protocol,
        caplen - SLL_HDR_LEN as u32,
        length - SLL_HDR_LEN as u32,
        data,
        SLL_HDR_LEN,
    );
}

fn swap_linux_sll2_socketcan_header(caplen: u32, length: u32, data: &mut [u8]) {
    if caplen < SLL2_HDR_LEN as u32 || length < SLL2_HDR_LEN as u32 {
        return;
    }
    let protocol = extract_be_u2(data, 0); // sll2_header.sll2_protocol @0
    swap_socketcan_header(
        protocol,
        caplen - SLL2_HDR_LEN as u32,
        length - SLL2_HDR_LEN as u32,
        data,
        SLL2_HDR_LEN,
    );
}

// --- swap_linux_usb_header: the offset-tracked field walk from pcap-util.c, verbatim in offsets.
//     `header_len_64_bytes` distinguishes DLT_USB_LINUX (false) from DLT_USB_LINUX_MMAPPED (true).
fn swap_linux_usb_header(caplen: u32, data: &mut [u8], header_len_64_bytes: bool) {
    let transfer_type = if data.len() > 9 { data[9] } else { 0 }; // uhdr->transfer_type @9
    let mut offset: u32 = 0;

    offset += 8; // skip past id
    if caplen < offset {
        return;
    }
    swap_bytes(data, 0, 8); // id

    offset += 4; // skip various 1-byte fields
    offset += 2; // skip past bus_id
    if caplen < offset {
        return;
    }
    swap_bytes(data, 12, 2); // bus_id

    offset += 2; // skip various 1-byte fields
    offset += 8; // skip past ts_sec
    if caplen < offset {
        return;
    }
    swap_bytes(data, 16, 8); // ts_sec

    offset += 4; // skip past ts_usec
    if caplen < offset {
        return;
    }
    swap_bytes(data, 24, 4); // ts_usec

    offset += 4; // skip past status
    if caplen < offset {
        return;
    }
    swap_bytes(data, 28, 4); // status

    offset += 4; // skip past urb_len
    if caplen < offset {
        return;
    }
    swap_bytes(data, 32, 4); // urb_len

    offset += 4; // skip past data_len
    if caplen < offset {
        return;
    }
    swap_bytes(data, 36, 4); // data_len

    if transfer_type == URB_ISOCHRONOUS {
        offset += 4; // skip past s.iso.error_count
        if caplen < offset {
            return;
        }
        swap_bytes(data, 40, 4); // s.iso.error_count

        offset += 4; // skip past s.iso.numdesc
        if caplen < offset {
            return;
        }
        swap_bytes(data, 44, 4); // s.iso.numdesc
    } else {
        offset += 8; // skip USB setup header
    }

    if header_len_64_bytes {
        offset += 4; // skip past interval
        if caplen < offset {
            return;
        }
        swap_bytes(data, 48, 4); // interval

        offset += 4; // skip past start_frame
        if caplen < offset {
            return;
        }
        swap_bytes(data, 52, 4); // start_frame

        offset += 4; // skip past xfer_flags
        if caplen < offset {
            return;
        }
        swap_bytes(data, 56, 4); // xfer_flags

        offset += 4; // skip past ndesc
        if caplen < offset {
            return;
        }
        swap_bytes(data, 60, 4); // ndesc

        if transfer_type == URB_ISOCHRONOUS {
            // ndesc is read AFTER its own swap, matching the C.
            let ndesc = rd_u32_host(data, 60);
            let mut desc_base: usize = 64;
            let mut i: u32 = 0;
            while i < ndesc {
                offset += 4; // skip past status
                if caplen < offset {
                    return;
                }
                swap_bytes(data, desc_base, 4); // status

                offset += 4; // skip past offset
                if caplen < offset {
                    return;
                }
                swap_bytes(data, desc_base + 4, 4); // offset

                offset += 4; // skip past len
                if caplen < offset {
                    return;
                }
                swap_bytes(data, desc_base + 8, 4); // len

                offset += 4; // skip past padding
                desc_base += 16;
                i += 1;
            }
        }
    }
}

// --- swap_nflog_header: fixed BE header, then TLVs whose type/length are host-order ---
fn swap_nflog_header(caplen: u32, length: u32, data: &mut [u8]) {
    if caplen < NFLOG_HDR_LEN || length < NFLOG_HDR_LEN {
        return;
    }
    if data[1] != 0 {
        // nflog_version @1 (nflog_hdr_t.nflog_version); unknown version
        return;
    }

    let mut caplen = caplen - NFLOG_HDR_LEN;
    let mut length = length - NFLOG_HDR_LEN;
    let mut p: usize = NFLOG_HDR_LEN as usize;

    while caplen >= NFLOG_TLV_LEN {
        // nflog_tlv_t: tlv_length @0, tlv_type @2.
        swap_bytes(data, p + 2, 2); // tlv_type
        swap_bytes(data, p, 2); // tlv_length

        let mut size = rd_u16_host(data, p) as u32; // the just-swapped tlv_length
        if !size.is_multiple_of(4) {
            size += 4 - size % 4;
        }
        if size < NFLOG_TLV_LEN {
            return;
        }
        if caplen < size || length < size {
            return;
        }
        length -= size;
        caplen -= size;
        p += size as usize;
    }
}

fn swap_pseudo_headers(linktype: u32, caplen: u32, length: u32, data: &mut [u8]) {
    match linktype {
        DLT_PFLOG => swap_pflog_header(caplen, length, data),
        DLT_LINUX_SLL => swap_linux_sll_socketcan_header(caplen, length, data),
        DLT_LINUX_SLL2 => swap_linux_sll2_socketcan_header(caplen, length, data),
        DLT_USB_LINUX => swap_linux_usb_header(caplen, data, false),
        DLT_USB_LINUX_MMAPPED => swap_linux_usb_header(caplen, data, true),
        DLT_NFLOG => swap_nflog_header(caplen, length, data),
        _ => {}
    }
}

/// `iso_pseudo_header_len`: mmapped header + all isochronous descriptors (ndesc <= USB_MAXDESC,
/// so this can't overflow).
fn iso_pseudo_header_len(ndesc: u32) -> u32 {
    USB_MMAPPED_HDR_LEN + ndesc * USB_ISODESC_LEN
}

/// `packet_length_might_be_wrong`: the old-style length (computed the pre-fix way, with wrapping
/// arithmetic as it would have been at capture time) equals the stored length.
fn packet_length_might_be_wrong(len: u32, ndesc: u32, urb_len: u32) -> bool {
    let old_style_packet_length = iso_pseudo_header_len(ndesc).wrapping_add(urb_len);
    len == old_style_packet_length
}

/// `incoming_isochronous_transfer_completed_len`: recompute the packet length from the
/// isochronous descriptors' offset/len fields (the data is scattered, so `urb_len` is wrong).
fn incoming_isochronous_transfer_completed_len(caplen: u32, ndesc: u32, data: &[u8]) -> u32 {
    let mut bytes_left = caplen - USB_MMAPPED_HDR_LEN; // caller ensured caplen >= 64
    let mut pre_truncation_data_len: u32 = 0;
    let mut desc: u32 = 0;
    while desc < ndesc && bytes_left >= USB_ISODESC_LEN {
        let desc_off = 64 + (desc as usize) * 16;
        let dlen = rd_u32_host(data, desc_off + 8); // usb_isodesc.len @8
        if dlen != 0 {
            let doff = rd_u32_host(data, desc_off + 4); // usb_isodesc.offset @4
            let desc_end = u_int_sum(doff, dlen);
            if desc_end > pre_truncation_data_len {
                pre_truncation_data_len = desc_end;
            }
        }
        bytes_left -= USB_ISODESC_LEN;
        desc += 1;
    }
    u_int_sum(iso_pseudo_header_len(ndesc), pre_truncation_data_len)
}

/// Port of `pcapint_post_process(linktype, swapped, hdr, data)`. `caplen`/`len` are the packet
/// header's fields (`len` mutable — the USB fixup can change it); `data` is the captured bytes
/// (`data.len() == caplen`), byte-swapped in place.
pub fn post_process(linktype: u32, swapped: bool, caplen: u32, len: &mut u32, data: &mut [u8]) {
    // `swapped` is host-relative (`pcap_check_header` computes it as file-order ≠ reading-host
    // order; libpcap#1702), so it directly gates the swap of the pseudo-header into reading-host
    // order — matching upstream's `if (swapped)`.
    if swapped {
        swap_pseudo_headers(linktype, caplen, *len, data);
    }

    // Memory-mapped Linux USB capture: fix the miscalculated original length of incoming
    // isochronous transfer completion events. Runs whether or not the file was byte-swapped.
    if linktype == DLT_USB_LINUX_MMAPPED {
        if caplen < USB_MMAPPED_HDR_LEN {
            return; // not the full pseudo-header
        }
        let ndesc = rd_u32_host(data, 60); // uhdr->ndesc @60 (already reading-host order)
        if ndesc > USB_MAXDESC {
            return; // insane descriptor count; don't trust it
        }
        let data_flag = data[15]; // uhdr->data_flag @15 (0 means data IS present)
        let event_type = data[8]; // uhdr->event_type @8
        let transfer_type = data[9]; // uhdr->transfer_type @9
        let endpoint_number = data[10]; // uhdr->endpoint_number @10
        let is_iso_completion = transfer_type == URB_ISOCHRONOUS
            && event_type == URB_COMPLETE
            && (endpoint_number & URB_TRANSFER_IN) != 0;
        let urb_len = rd_u32_host(data, 32); // uhdr->urb_len @32

        if data_flag == 0 && is_iso_completion && packet_length_might_be_wrong(*len, ndesc, urb_len)
        {
            if caplen < iso_pseudo_header_len(ndesc) {
                return; // don't have all the descriptors
            }
            let new_len = incoming_isochronous_transfer_completed_len(caplen, ndesc, data);
            if new_len >= caplen {
                *len = new_len;
            }
            if caplen > *len {
                *len = caplen;
            }
        }
    }
}
