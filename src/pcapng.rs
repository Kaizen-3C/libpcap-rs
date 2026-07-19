//! pcapng block-parser: `pcap_ng_check_header` (SHB detection + first-section IDB) and
//! `pcap_ng_next_packet` (EPB/SPB/PB/IDB/SHB block loop, per-interface timestamp scaling).
//! Ported verbatim in control flow from libpcap 1.10.5 `src/sf-pcapng.c`; differentially
//! certified against the upstream C build (see `../HARNESS.md` and `../README.md`).

const PCAP_ERRBUF_SIZE: usize = 256;
const MAXIMUM_SNAPLEN: u32 = 262144;
const PCAP_TSTAMP_PRECISION_MICRO: u32 = 0;
const PCAP_TSTAMP_PRECISION_NANO: u32 = 1;

const BT_SHB: u32 = 0x0A0D0D0A;
const BT_SHB_INSANE_MAX: u32 = 1024 * 1024;
const BT_IDB: u32 = 0x00000001;
const BT_EPB: u32 = 0x00000006;
const BT_SPB: u32 = 0x00000003;
const BT_PB: u32 = 0x00000002;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
const PCAP_NG_VERSION_MAJOR: u16 = 1;
const PCAP_NG_VERSION_MINOR: u16 = 0;

const OPT_ENDOFOPT: u16 = 0;
const IF_TSRESOL: u16 = 9;
const IF_TSOFFSET: u16 = 14;

const INITIAL_MAX_BLOCKSIZE: u32 = 16 * 1024 * 1024;

#[allow(dead_code)]
const PCAP_ERRBUF_SIZE_CONST: usize = PCAP_ERRBUF_SIZE;

#[derive(Debug, Clone, Copy)]
enum TstampScaleType {
    PassThrough,
    ScaleUpDec,
    ScaleDownDec,
    ScaleUpBin,
    ScaleDownBin,
}

#[derive(Debug, Clone)]
struct PcapNgIf {
    #[allow(dead_code)]
    snaplen: u32,
    tsresol: u64,
    scale_type: TstampScaleType,
    scale_factor: u64,
    tsoffset: i64,
}

#[derive(Debug)]
struct PcapNgSf {
    user_tsresol: u64,
    max_blocksize: u32,
    ifcount: u32,
    ifaces_size: u32,
    ifaces: Vec<PcapNgIf>,
}

#[derive(Debug)]
pub struct PcapPkthdr {
    pub ts_sec: i64,
    pub ts_usec: i64,
    pub caplen: u32,
    pub len: u32,
}

#[derive(Debug)]
struct BlockCursor {
    data: Vec<u8>,
    data_offset: usize,
    block_type: u32,
}

pub struct Pcap {
    rfile: Option<Vec<u8>>,
    rfile_pos: usize,
    priv_data: PcapNgSf,
    /// Host-relative (libpcap semantics: section byte order ≠ reading host's); gates `post_process`.
    pub swapped: bool,
    /// Absolute: the section is big-endian, host-independent; gates the `from_le_bytes` block-field
    /// decode corrections. Equals `swapped` on a little-endian host (libpcap#1702).
    pub file_is_be: bool,
    pub version_major: u16,
    pub version_minor: u16,
    pub linktype: u32,
    #[allow(dead_code)]
    linktype_ext: u32,
    pub snapshot: i32,
    buffer: Vec<u8>,
    pub errbuf: String,
    #[allow(dead_code)]
    tstamp_precision: u32,
}

fn swap_long(x: u32) -> u32 {
    (((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | ((x) >> 24)
}

fn swap_short(x: u16) -> u16 {
    (((x) & 0xff) << 8) | (((x) & 0xff00) >> 8)
}

fn swap_ll(ull: u64) -> u64 {
    ((ull & 0xff00000000000000) >> 56)
        | ((ull & 0x00ff000000000000) >> 40)
        | ((ull & 0x0000ff0000000000) >> 24)
        | ((ull & 0x000000ff00000000) >> 8)
        | ((ull & 0x00000000ff000000) << 8)
        | ((ull & 0x0000000000ff0000) << 24)
        | ((ull & 0x000000000000ff00) << 40)
        | ((ull & 0x00000000000000ff) << 56)
}

fn read_bytes(pcap: &mut Pcap, buf: &mut [u8], fail_on_eof: bool) -> i32 {
    if let Some(ref data) = pcap.rfile {
        let to_read = buf.len();
        let available = data.len().saturating_sub(pcap.rfile_pos);
        if available < to_read {
            if available == 0 && !fail_on_eof {
                return 0;
            }
            pcap.errbuf = format!(
                "truncated pcapng dump file; tried to read {} bytes, only got {}",
                to_read, available
            );
            return -1;
        }
        buf.copy_from_slice(&data[pcap.rfile_pos..pcap.rfile_pos + to_read]);
        pcap.rfile_pos += to_read;
        1
    } else {
        -1
    }
}

fn read_block(pcap: &mut Pcap, cursor: &mut BlockCursor) -> i32 {
    let mut bhdr = [0u8; 8];
    let status = read_bytes(pcap, &mut bhdr, false);
    if status <= 0 {
        return status;
    }

    let mut block_type = u32::from_le_bytes([bhdr[0], bhdr[1], bhdr[2], bhdr[3]]);
    let mut total_length = u32::from_le_bytes([bhdr[4], bhdr[5], bhdr[6], bhdr[7]]);

    if pcap.file_is_be {
        block_type = swap_long(block_type);
        total_length = swap_long(total_length);
    }

    if total_length < 12 {
        pcap.errbuf = format!(
            "block in pcapng dump file has a length of {} < 12",
            total_length
        );
        return -1;
    }

    if (total_length % 4) != 0 {
        pcap.errbuf = format!(
            "block in pcapng dump file has a length of {} that is not a multiple of 4",
            total_length
        );
        return -1;
    }

    if pcap.buffer.len() < total_length as usize {
        if total_length > pcap.priv_data.max_blocksize {
            pcap.errbuf = format!(
                "pcapng block size {} > maximum {}",
                total_length, pcap.priv_data.max_blocksize
            );
            return -1;
        }
        pcap.buffer.resize(total_length as usize, 0);
    }

    pcap.buffer[0..8].copy_from_slice(&bhdr);
    let bdata_start = 8;
    let full_remaining = (total_length as usize) - 8;

    let mut bdata = vec![0u8; full_remaining];
    let status = read_bytes(pcap, &mut bdata, true);
    if status == -1 {
        return -1;
    }

    pcap.buffer[bdata_start..bdata_start + full_remaining].copy_from_slice(&bdata);

    let trailer_offset = full_remaining - 4;
    let mut btrlr_bytes = [0u8; 4];
    btrlr_bytes.copy_from_slice(
        &pcap.buffer[bdata_start + trailer_offset..bdata_start + trailer_offset + 4],
    );
    let mut btrlr_total_length = u32::from_le_bytes(btrlr_bytes);

    if pcap.file_is_be {
        btrlr_total_length = swap_long(btrlr_total_length);
    }

    if total_length != btrlr_total_length {
        pcap.errbuf = "block total length in header and trailer don't match".to_string();
        return -1;
    }

    cursor.data = pcap.buffer[bdata_start..bdata_start + full_remaining - 4].to_vec();
    cursor.data_offset = 0;
    cursor.block_type = block_type;
    1
}

fn get_from_block_data(
    pcap: &mut Pcap,
    cursor: &mut BlockCursor,
    chunk_size: usize,
) -> Option<Vec<u8>> {
    if cursor.data.len() - cursor.data_offset < chunk_size {
        pcap.errbuf = format!(
            "block of type {} in pcapng dump file is too short",
            cursor.block_type
        );
        return None;
    }
    let result = cursor.data[cursor.data_offset..cursor.data_offset + chunk_size].to_vec();
    cursor.data_offset += chunk_size;
    Some(result)
}

fn get_opthdr_from_block_data(pcap: &mut Pcap, cursor: &mut BlockCursor) -> Option<(u16, u16)> {
    let data = get_from_block_data(pcap, cursor, 4)?;
    let mut option_code = u16::from_le_bytes([data[0], data[1]]);
    let mut option_length = u16::from_le_bytes([data[2], data[3]]);

    if pcap.file_is_be {
        option_code = swap_short(option_code);
        option_length = swap_short(option_length);
    }

    Some((option_code, option_length))
}

fn get_optvalue_from_block_data(
    pcap: &mut Pcap,
    cursor: &mut BlockCursor,
    option_length: u16,
) -> Option<Vec<u8>> {
    let padded_option_len = (option_length as usize).div_ceil(4) * 4;
    get_from_block_data(pcap, cursor, padded_option_len)
}

fn process_idb_options(pcap: &mut Pcap, cursor: &mut BlockCursor) -> Result<(u64, i64, i32), i32> {
    let mut tsresol = 1000000u64;
    let mut tsoffset = 0i64;
    let mut is_binary = 0i32;
    let mut saw_tsresol = false;
    let mut saw_tsoffset = false;

    loop {
        if cursor.data_offset >= cursor.data.len() {
            break;
        }

        let (option_code, option_length) = match get_opthdr_from_block_data(pcap, cursor) {
            Some(x) => x,
            None => return Err(-1),
        };

        let optvalue = match get_optvalue_from_block_data(pcap, cursor, option_length) {
            Some(x) => x,
            None => return Err(-1),
        };

        match option_code {
            OPT_ENDOFOPT => {
                if option_length != 0 {
                    pcap.errbuf = format!(
                        "Interface Description Block has opt_endofopt option with length {} != 0",
                        option_length
                    );
                    return Err(-1);
                }
                break;
            }
            IF_TSRESOL => {
                if option_length != 1 {
                    pcap.errbuf = format!(
                        "Interface Description Block has if_tsresol option with length {} != 1",
                        option_length
                    );
                    return Err(-1);
                }
                if saw_tsresol {
                    pcap.errbuf = "Interface Description Block has more than one if_tsresol option"
                        .to_string();
                    return Err(-1);
                }
                saw_tsresol = true;
                let tsresol_opt = optvalue[0];
                if (tsresol_opt & 0x80) != 0 {
                    let tsresol_shift = tsresol_opt & 0x7F;
                    if tsresol_shift > 63 {
                        pcap.errbuf = format!(
                            "Interface Description Block if_tsresol option resolution 2^-{} is too high",
                            tsresol_shift
                        );
                        return Err(-1);
                    }
                    is_binary = 1;
                    tsresol = 1u64 << tsresol_shift;
                } else {
                    if tsresol_opt > 19 {
                        pcap.errbuf = format!(
                            "Interface Description Block if_tsresol option resolution 10^-{} is too high",
                            tsresol_opt
                        );
                        return Err(-1);
                    }
                    is_binary = 0;
                    tsresol = 1;
                    for _ in 0..tsresol_opt {
                        tsresol *= 10;
                    }
                }
            }
            IF_TSOFFSET => {
                if option_length != 8 {
                    pcap.errbuf = format!(
                        "Interface Description Block has if_tsoffset option with length {} != 8",
                        option_length
                    );
                    return Err(-1);
                }
                if saw_tsoffset {
                    pcap.errbuf =
                        "Interface Description Block has more than one if_tsoffset option"
                            .to_string();
                    return Err(-1);
                }
                saw_tsoffset = true;
                tsoffset = i64::from_le_bytes([
                    optvalue[0],
                    optvalue[1],
                    optvalue[2],
                    optvalue[3],
                    optvalue[4],
                    optvalue[5],
                    optvalue[6],
                    optvalue[7],
                ]);
                if pcap.file_is_be {
                    tsoffset = swap_ll(tsoffset as u64) as i64;
                }
            }
            _ => {}
        }
    }

    Ok((tsresol, tsoffset, is_binary))
}

fn add_interface(
    pcap: &mut Pcap,
    _idbp_linktype: u16,
    idbp_snaplen: u32,
    cursor: &mut BlockCursor,
) -> bool {
    pcap.priv_data.ifcount += 1;

    if pcap.priv_data.ifcount > pcap.priv_data.ifaces_size {
        let new_ifaces_size = if pcap.priv_data.ifaces_size == 0 {
            1
        } else {
            if pcap.priv_data.ifaces_size * 2 < pcap.priv_data.ifaces_size {
                pcap.errbuf = format!("more than {} interfaces in the file", 0x80000000u32);
                return false;
            }
            pcap.priv_data.ifaces_size * 2
        };

        pcap.priv_data.ifaces.resize(
            new_ifaces_size as usize,
            PcapNgIf {
                snaplen: 0,
                tsresol: 0,
                scale_type: TstampScaleType::PassThrough,
                scale_factor: 0,
                tsoffset: 0,
            },
        );
        pcap.priv_data.ifaces_size = new_ifaces_size;
    }

    let idx = (pcap.priv_data.ifcount - 1) as usize;
    pcap.priv_data.ifaces[idx].snaplen = idbp_snaplen;

    let (tsresol, tsoffset, is_binary) = match process_idb_options(pcap, cursor) {
        Ok(x) => x,
        Err(_) => return false,
    };

    pcap.priv_data.ifaces[idx].tsresol = tsresol;
    pcap.priv_data.ifaces[idx].tsoffset = tsoffset;

    if tsresol == pcap.priv_data.user_tsresol {
        pcap.priv_data.ifaces[idx].scale_type = TstampScaleType::PassThrough;
    } else if tsresol > pcap.priv_data.user_tsresol {
        if is_binary != 0 {
            pcap.priv_data.ifaces[idx].scale_type = TstampScaleType::ScaleDownBin;
        } else {
            pcap.priv_data.ifaces[idx].scale_factor = tsresol / pcap.priv_data.user_tsresol;
            pcap.priv_data.ifaces[idx].scale_type = TstampScaleType::ScaleDownDec;
        }
    } else if is_binary != 0 {
        pcap.priv_data.ifaces[idx].scale_type = TstampScaleType::ScaleUpBin;
    } else {
        pcap.priv_data.ifaces[idx].scale_factor = pcap.priv_data.user_tsresol / tsresol;
        pcap.priv_data.ifaces[idx].scale_type = TstampScaleType::ScaleUpDec;
    }

    true
}

fn pcapint_adjust_snapshot(_linktype: u32, snaplen: u32) -> u32 {
    if snaplen == 0 || snaplen > MAXIMUM_SNAPLEN {
        MAXIMUM_SNAPLEN
    } else {
        snaplen
    }
}

pub fn pcap_ng_check_header(
    magic: &[u8; 4],
    pcap_data: &[u8],
    precision: u32,
) -> Result<Pcap, String> {
    let magic_int = u32::from_le_bytes(*magic);
    if magic_int != BT_SHB {
        return Err("not-pcapng".to_string());
    }

    if pcap_data.len() < 8 {
        return Err("not-pcapng".to_string());
    }

    let total_length_raw =
        u32::from_le_bytes([pcap_data[0], pcap_data[1], pcap_data[2], pcap_data[3]]);
    let byte_order_magic_raw =
        u32::from_le_bytes([pcap_data[4], pcap_data[5], pcap_data[6], pcap_data[7]]);

    let mut byte_order_magic = byte_order_magic_raw;
    let mut swapped = false;
    let mut total_length = total_length_raw;

    if byte_order_magic != BYTE_ORDER_MAGIC {
        byte_order_magic = swap_long(byte_order_magic);
        if byte_order_magic != BYTE_ORDER_MAGIC {
            return Err("not-pcapng".to_string());
        }
        swapped = true;
        total_length = swap_long(total_length);
    }

    let min_shb_size: u32 = 8 + 16 + 4;
    if total_length < min_shb_size || total_length > BT_SHB_INSANE_MAX {
        return Err(format!(
            "Section Header Block in pcapng dump file has invalid length {} < _{}_ < {} (BT_SHB_INSANE_MAX)",
            min_shb_size, total_length, BT_SHB_INSANE_MAX
        ));
    }

    let mut pcap = Pcap {
        rfile: Some(pcap_data.to_vec()),
        rfile_pos: 8,
        priv_data: PcapNgSf {
            user_tsresol: match precision {
                PCAP_TSTAMP_PRECISION_MICRO => 1000000,
                PCAP_TSTAMP_PRECISION_NANO => 1000000000,
                _ => return Err(format!("unknown time stamp resolution {}", precision)),
            },
            max_blocksize: INITIAL_MAX_BLOCKSIZE,
            ifcount: 0,
            ifaces_size: 0,
            ifaces: Vec::new(),
        },
        // `swapped` here is the ABSOLUTE "section is big-endian" (host-independent BOM read). Store
        // the field as libpcap's HOST-RELATIVE flag (byte order ≠ reading host's) for post_process /
        // callers, and keep the absolute one as `file_is_be` for the block-field decode corrections
        // (libpcap#1702). No-op on a little-endian host.
        swapped: swapped ^ cfg!(target_endian = "big"),
        file_is_be: swapped,
        version_major: 0,
        version_minor: 0,
        linktype: 0,
        linktype_ext: 0,
        snapshot: 0,
        buffer: vec![0u8; 2048.max(total_length as usize)],
        errbuf: String::new(),
        tstamp_precision: precision,
    };

    let remaining = total_length as usize - 12;
    let mut shb_rest = vec![0u8; remaining];
    let status = read_bytes(&mut pcap, &mut shb_rest, true);
    if status == -1 {
        return Err(pcap.errbuf.clone());
    }

    if shb_rest.len() < 4 {
        return Err("Section Header Block too short".to_string());
    }

    let mut major_version = u16::from_le_bytes([shb_rest[0], shb_rest[1]]);
    let mut minor_version = u16::from_le_bytes([shb_rest[2], shb_rest[3]]);

    if swapped {
        major_version = swap_short(major_version);
        minor_version = swap_short(minor_version);
    }

    if !(major_version == PCAP_NG_VERSION_MAJOR
        && (minor_version == PCAP_NG_VERSION_MINOR || minor_version == 2))
    {
        return Err(format!(
            "unsupported pcapng savefile version {}.{}",
            major_version, minor_version
        ));
    }

    pcap.version_major = major_version;
    pcap.version_minor = minor_version;

    let mut cursor = BlockCursor {
        data: Vec::new(),
        data_offset: 0,
        block_type: 0,
    };

    loop {
        let status = read_block(&mut pcap, &mut cursor);
        if status == 0 {
            return Err("the capture file has no Interface Description Blocks".to_string());
        }
        if status != 1 {
            return Err(pcap.errbuf.clone());
        }

        match cursor.block_type {
            BT_IDB => {
                let idb_data = match get_from_block_data(&mut pcap, &mut cursor, 8) {
                    Some(x) => x,
                    None => return Err(pcap.errbuf.clone()),
                };

                let mut linktype = u16::from_le_bytes([idb_data[0], idb_data[1]]);
                let mut snaplen =
                    u32::from_le_bytes([idb_data[4], idb_data[5], idb_data[6], idb_data[7]]);

                if pcap.file_is_be {
                    linktype = swap_short(linktype);
                    snaplen = swap_long(snaplen);
                }

                if !add_interface(&mut pcap, linktype, snaplen, &mut cursor) {
                    return Err(pcap.errbuf.clone());
                }

                pcap.linktype = linktype as u32;
                pcap.snapshot = pcapint_adjust_snapshot(pcap.linktype, snaplen) as i32;
                pcap.linktype_ext = 0;

                return Ok(pcap);
            }
            BT_EPB | BT_SPB | BT_PB => {
                return Err(
                    "the capture file has a packet block before any Interface Description Blocks"
                        .to_string(),
                );
            }
            _ => {}
        }
    }
}

fn finish_packet(
    pcap: &mut Pcap,
    hdr: &mut PcapPkthdr,
    cursor: &mut BlockCursor,
    interface_id: u32,
    t: u64,
) -> Result<Vec<u8>, i32> {
    if interface_id >= pcap.priv_data.ifcount {
        pcap.errbuf = format!(
            "a packet arrived on interface {}, but there's no Interface Description Block for that interface",
            interface_id
        );
        return Err(-1);
    }

    if hdr.caplen > pcap.snapshot as u32 {
        pcap.errbuf = format!(
            "invalid packet capture length {}, bigger than snaplen of {}",
            hdr.caplen, pcap.snapshot
        );
        return Err(-1);
    }

    let (tsresol, tsoffset, scale_type, scale_factor, user_tsresol) = {
        let iface = &pcap.priv_data.ifaces[interface_id as usize];
        (
            iface.tsresol,
            iface.tsoffset,
            iface.scale_type,
            iface.scale_factor,
            pcap.priv_data.user_tsresol,
        )
    };

    let sec = (t / tsresol).wrapping_add(tsoffset as u64);
    let mut frac = t % tsresol;

    // C's uint64_t arithmetic here is naturally wrapping (no UB, no trap) — `frac` can be
    // large (tsresol comes from an attacker-controlled if_tsresol binary-exponent option, up
    // to 1u64<<63) and these multiplies can genuinely overflow 64 bits on adversarial input.
    // A fuzz run with debug-assertions on (cargo-fuzz always enables them) found the resulting
    // panic within a few million executions of extended, deeper fuzzing (not the initial
    // 15-minute runs — this needed real depth). The *shipped* release build (overflow-checks
    // off by default) already wraps identically to C, so this was never an observable
    // behavioral divergence, only a debug/fuzz-build robustness gap — but forbid(unsafe_code)
    // is only as good as "never panics on adversarial input" too, and a plain user `cargo
    // build` (no --release) would have hit this same panic on a real malicious pcapng file.
    // wrapping_mul makes the C-faithful wraparound explicit instead of relying on the release
    // profile's overflow-checks default.
    match scale_type {
        TstampScaleType::PassThrough => {}
        TstampScaleType::ScaleUpDec => {
            frac = frac.wrapping_mul(scale_factor);
        }
        TstampScaleType::ScaleUpBin => {
            frac = frac.wrapping_mul(user_tsresol);
            frac /= tsresol;
        }
        TstampScaleType::ScaleDownDec => {
            frac /= scale_factor;
        }
        TstampScaleType::ScaleDownBin => {
            frac = frac.wrapping_mul(user_tsresol);
            frac /= tsresol;
        }
    }

    hdr.ts_sec = sec as i64;
    hdr.ts_usec = frac as i64;

    let mut data = match get_from_block_data(pcap, cursor, hdr.caplen as usize) {
        Some(x) => x,
        None => return Err(-1),
    };

    // Tail of upstream pcap_ng_next_packet: same post-processing as the classic path
    // (libpcap#1702). p->linktype is the section's single link type (all IDBs must agree) and
    // p->swapped its byte-order flag; the USB fixup can adjust hdr.len.
    crate::post_process::post_process(
        pcap.linktype,
        pcap.swapped,
        hdr.caplen,
        &mut hdr.len,
        &mut data,
    );

    Ok(data)
}

pub fn pcap_ng_next_packet(pcap: &mut Pcap, hdr: &mut PcapPkthdr) -> Result<Vec<u8>, i32> {
    loop {
        let mut cursor = BlockCursor {
            data: Vec::new(),
            data_offset: 0,
            block_type: 0,
        };

        let status = read_block(pcap, &mut cursor);
        if status == 0 {
            return Err(0);
        }
        if status != 1 {
            return Err(-1);
        }

        match cursor.block_type {
            BT_EPB => {
                let epb_data = match get_from_block_data(pcap, &mut cursor, 20) {
                    Some(x) => x,
                    None => return Err(-1),
                };

                let interface_id_raw =
                    u32::from_le_bytes([epb_data[0], epb_data[1], epb_data[2], epb_data[3]]);
                let th_raw =
                    u32::from_le_bytes([epb_data[4], epb_data[5], epb_data[6], epb_data[7]]);
                let tl_raw =
                    u32::from_le_bytes([epb_data[8], epb_data[9], epb_data[10], epb_data[11]]);
                let caplen_raw =
                    u32::from_le_bytes([epb_data[12], epb_data[13], epb_data[14], epb_data[15]]);
                let len_raw =
                    u32::from_le_bytes([epb_data[16], epb_data[17], epb_data[18], epb_data[19]]);

                let (interface_id, caplen, len, t);
                if pcap.file_is_be {
                    interface_id = swap_long(interface_id_raw);
                    caplen = swap_long(caplen_raw);
                    len = swap_long(len_raw);
                    t = ((swap_long(th_raw) as u64) << 32) | (swap_long(tl_raw) as u64);
                } else {
                    interface_id = interface_id_raw;
                    caplen = caplen_raw;
                    len = len_raw;
                    t = ((th_raw as u64) << 32) | (tl_raw as u64);
                }

                hdr.caplen = caplen;
                hdr.len = len;

                return finish_packet(pcap, hdr, &mut cursor, interface_id, t);
            }
            BT_SPB => {
                let spb_data = match get_from_block_data(pcap, &mut cursor, 4) {
                    Some(x) => x,
                    None => return Err(-1),
                };

                let mut len =
                    u32::from_le_bytes([spb_data[0], spb_data[1], spb_data[2], spb_data[3]]);
                if pcap.file_is_be {
                    len = swap_long(len);
                }

                hdr.len = len;
                hdr.caplen = if len > pcap.snapshot as u32 {
                    pcap.snapshot as u32
                } else {
                    len
                };

                return finish_packet(pcap, hdr, &mut cursor, 0, 0);
            }
            BT_PB => {
                let pb_data = match get_from_block_data(pcap, &mut cursor, 20) {
                    Some(x) => x,
                    None => return Err(-1),
                };

                let interface_id_raw = u16::from_le_bytes([pb_data[0], pb_data[1]]);
                let th_raw = u32::from_le_bytes([pb_data[4], pb_data[5], pb_data[6], pb_data[7]]);
                let tl_raw = u32::from_le_bytes([pb_data[8], pb_data[9], pb_data[10], pb_data[11]]);
                let caplen_raw =
                    u32::from_le_bytes([pb_data[12], pb_data[13], pb_data[14], pb_data[15]]);
                let len_raw =
                    u32::from_le_bytes([pb_data[16], pb_data[17], pb_data[18], pb_data[19]]);

                let (interface_id, caplen, len, t);
                if pcap.file_is_be {
                    interface_id = swap_short(interface_id_raw) as u32;
                    caplen = swap_long(caplen_raw);
                    len = swap_long(len_raw);
                    t = ((swap_long(th_raw) as u64) << 32) | (swap_long(tl_raw) as u64);
                } else {
                    interface_id = interface_id_raw as u32;
                    caplen = caplen_raw;
                    len = len_raw;
                    t = ((th_raw as u64) << 32) | (tl_raw as u64);
                }

                hdr.caplen = caplen;
                hdr.len = len;

                return finish_packet(pcap, hdr, &mut cursor, interface_id, t);
            }
            BT_IDB => {
                let idb_data = match get_from_block_data(pcap, &mut cursor, 8) {
                    Some(x) => x,
                    None => return Err(-1),
                };

                let mut linktype = u16::from_le_bytes([idb_data[0], idb_data[1]]);
                let mut snaplen =
                    u32::from_le_bytes([idb_data[4], idb_data[5], idb_data[6], idb_data[7]]);

                if pcap.file_is_be {
                    linktype = swap_short(linktype);
                    snaplen = swap_long(snaplen);
                }

                if pcap.linktype != linktype as u32 {
                    pcap.errbuf = format!(
                        "an interface has a type {} different from the type of the first interface",
                        linktype
                    );
                    return Err(-1);
                }

                if pcap.snapshot as u32 != pcapint_adjust_snapshot(pcap.linktype, snaplen) {
                    pcap.errbuf = format!(
                        "an interface has a snapshot length {} different from the snapshot length of the first interface",
                        snaplen
                    );
                    return Err(-1);
                }

                if !add_interface(pcap, linktype, snaplen, &mut cursor) {
                    return Err(-1);
                }
            }
            BT_SHB => {
                let shb_data = match get_from_block_data(pcap, &mut cursor, 16) {
                    Some(x) => x,
                    None => return Err(-1),
                };

                let mut byte_order_magic =
                    u32::from_le_bytes([shb_data[0], shb_data[1], shb_data[2], shb_data[3]]);
                let mut major_version = u16::from_le_bytes([shb_data[4], shb_data[5]]);

                if pcap.file_is_be {
                    byte_order_magic = swap_long(byte_order_magic);
                    major_version = swap_short(major_version);
                }

                if byte_order_magic == BYTE_ORDER_MAGIC {
                    // ok
                } else if byte_order_magic == swap_long(BYTE_ORDER_MAGIC) {
                    pcap.errbuf = "the file has sections with different byte orders".to_string();
                    return Err(-1);
                } else {
                    pcap.errbuf =
                        "the file has a section with a bad byte order magic field".to_string();
                    return Err(-1);
                }

                if major_version != PCAP_NG_VERSION_MAJOR {
                    pcap.errbuf = format!(
                        "unknown pcapng savefile major version number {}",
                        major_version
                    );
                    return Err(-1);
                }

                pcap.priv_data.ifcount = 0;
            }
            _ => {}
        }
    }
}
