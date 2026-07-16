//! # libpcap-rs
//!
//! Memory-safe Rust port of the libpcap 1.10.5 classic-pcap *savefile parser* —
//! `pcap_check_header` (file-header validation, byte-order detection, version/linktype
//! checks) and `pcap_next_packet` (per-record parsing, timestamp scaling, caplen/len
//! swap heuristics, and the caplen/snapshot bounds checks). Reads from a byte buffer.
//!
//! Differentially certified against the upstream C build; see `README.md`.
//! The entire crate is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const MAXIMUM_SNAPLEN: u32 = 262144;

const TCPDUMP_MAGIC: u32 = 0xa1b2c3d4;
const KUZNETZOV_TCPDUMP_MAGIC: u32 = 0xa1b2cd34;
const NSEC_TCPDUMP_MAGIC: u32 = 0xa1b23c4d;

const DLT_EN10MB: u32 = 1;

#[derive(Clone, Copy, PartialEq)]
pub enum SwappedType {
    NotSwapped,
    Swapped,
    MaybeSwapped,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ScaleType {
    PassThrough,
    ScaleUp,
    ScaleDown,
}

pub struct PcapT {
    pub swapped: bool,
    pub version_major: u16,
    pub version_minor: u16,
    pub linktype: u32,
    pub snapshot: i32,
    pub bufsize: usize,
    pub buffer: Vec<u8>,
    pub hdrsize: usize,
    pub lengths_swapped: SwappedType,
    pub scale_type: ScaleType,
}

pub struct FileSim<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> FileSim<'a> {
    fn read(&mut self, n: usize) -> Vec<u8> {
        let avail = self.data.len().saturating_sub(self.pos);
        let take = avail.min(n);
        let out = self.data[self.pos..self.pos + take].to_vec();
        self.pos += take;
        out
    }
}

pub fn swap32(x: u32) -> u32 {
    x.swap_bytes()
}
pub fn swap16(x: u16) -> u16 {
    x.swap_bytes()
}

pub fn pcap_check_header(magic: [u8; 4], reader: &mut FileSim) -> (Option<PcapT>, String) {
    let mut magic_int = u32::from_le_bytes(magic);
    let mut swapped = false;
    if magic_int != TCPDUMP_MAGIC
        && magic_int != KUZNETZOV_TCPDUMP_MAGIC
        && magic_int != NSEC_TCPDUMP_MAGIC
    {
        magic_int = swap32(magic_int);
        if magic_int != TCPDUMP_MAGIC
            && magic_int != KUZNETZOV_TCPDUMP_MAGIC
            && magic_int != NSEC_TCPDUMP_MAGIC
        {
            return (None, String::new());
        }
        swapped = true;
    }

    let rest = reader.read(20);
    if rest.len() != 20 {
        let errbuf = format!(
            "truncated dump file; tried to read {} file header bytes, only got {}",
            24,
            rest.len()
        );
        return (None, errbuf);
    }

    let mut version_major = u16::from_le_bytes([rest[0], rest[1]]);
    let mut version_minor = u16::from_le_bytes([rest[2], rest[3]]);
    // thiszone, sigfigs unused for output but consumed
    let mut snaplen = u32::from_le_bytes([rest[12], rest[13], rest[14], rest[15]]);
    let mut linktype_field = u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]);

    if swapped {
        version_major = swap16(version_major);
        version_minor = swap16(version_minor);
        snaplen = swap32(snaplen);
        linktype_field = swap32(linktype_field);
    }

    if version_major < PCAP_VERSION_MAJOR {
        return (None, "archaic pcap savefile format".to_string());
    }

    if !((version_major == PCAP_VERSION_MAJOR && version_minor <= PCAP_VERSION_MINOR)
        || (version_major == 543 && version_minor == 0))
    {
        return (
            None,
            format!(
                "unsupported pcap savefile version {}.{}",
                version_major, version_minor
            ),
        );
    }

    let reserved1 = linktype_field & 0x03FF0000;
    if reserved1 != 0 {
        return (
            None,
            format!(
                "savefile linktype reserved field not zero (0x{:08x})",
                reserved1
            ),
        );
    }

    let lt_linktype = linktype_field & 0x0000FFFF;
    let linktype = lt_linktype; // linktype_to_dlt is identity

    let mut snapshot: i64 = if snaplen == 0 || snaplen > MAXIMUM_SNAPLEN {
        MAXIMUM_SNAPLEN as i64
    } else {
        snaplen as i64
    };

    let scale_type = if magic_int == NSEC_TCPDUMP_MAGIC {
        ScaleType::ScaleDown
    } else {
        ScaleType::PassThrough
    };

    let lengths_swapped = match version_major {
        2 => {
            if version_minor < 3 {
                SwappedType::Swapped
            } else if version_minor == 3 {
                SwappedType::MaybeSwapped
            } else {
                SwappedType::NotSwapped
            }
        }
        543 => SwappedType::Swapped,
        _ => SwappedType::NotSwapped,
    };

    let hdrsize;
    if magic_int == KUZNETZOV_TCPDUMP_MAGIC {
        hdrsize = 24usize;
        if linktype == DLT_EN10MB {
            if snapshot <= (i32::MAX as i64) - 14 {
                snapshot += 14;
            } else {
                snapshot = i32::MAX as i64;
            }
        }
    } else {
        hdrsize = 16usize;
    }

    let mut bufsize = snapshot as usize;
    if bufsize > 2048 {
        bufsize = 2048;
    }
    let buffer = vec![0u8; bufsize];

    let p = PcapT {
        swapped,
        version_major,
        version_minor,
        linktype,
        snapshot: snapshot as i32,
        bufsize,
        buffer,
        hdrsize,
        lengths_swapped,
        scale_type,
    };
    (Some(p), String::new())
}

pub fn grow_buffer(p: &mut PcapT, bufsize: usize) -> bool {
    p.buffer.resize(bufsize, 0);
    p.bufsize = bufsize;
    true
}

pub enum NextResult {
    Eof,
    Err(String),
    Packet {
        caplen: u32,
        len: u32,
        tv_sec: i64,
        tv_usec: i64,
    },
}

pub fn pcap_next_packet(p: &mut PcapT, reader: &mut FileSim) -> NextResult {
    let hdrbytes = reader.read(p.hdrsize);
    if hdrbytes.len() != p.hdrsize {
        if hdrbytes.is_empty() {
            return NextResult::Eof;
        } else {
            let msg = format!(
                "truncated dump file; tried to read {} header bytes, only got {}",
                p.hdrsize,
                hdrbytes.len()
            );
            return NextResult::Err(msg);
        }
    }

    let raw_tv_sec = i32::from_le_bytes([hdrbytes[0], hdrbytes[1], hdrbytes[2], hdrbytes[3]]);
    let raw_tv_usec = i32::from_le_bytes([hdrbytes[4], hdrbytes[5], hdrbytes[6], hdrbytes[7]]);
    let raw_caplen = u32::from_le_bytes([hdrbytes[8], hdrbytes[9], hdrbytes[10], hdrbytes[11]]);
    let raw_len = u32::from_le_bytes([hdrbytes[12], hdrbytes[13], hdrbytes[14], hdrbytes[15]]);

    let (mut caplen, mut len, tv_sec, tv_usec);
    if p.swapped {
        caplen = swap32(raw_caplen);
        len = swap32(raw_len);
        tv_sec = swap32(raw_tv_sec as u32) as i32;
        tv_usec = swap32(raw_tv_usec as u32) as i32;
    } else {
        caplen = raw_caplen;
        len = raw_len;
        tv_sec = raw_tv_sec;
        tv_usec = raw_tv_usec;
    }

    let tv_sec_i64 = tv_sec as i64;
    let mut tv_usec_i64 = tv_usec as i64;

    match p.scale_type {
        ScaleType::PassThrough => {}
        ScaleType::ScaleUp => {
            tv_usec_i64 *= 1000;
        }
        ScaleType::ScaleDown => {
            tv_usec_i64 /= 1000;
        }
    }

    match p.lengths_swapped {
        SwappedType::NotSwapped => {}
        SwappedType::MaybeSwapped => {
            if caplen <= len {
                // no swap
            } else {
                std::mem::swap(&mut caplen, &mut len);
            }
        }
        SwappedType::Swapped => {
            std::mem::swap(&mut caplen, &mut len);
        }
    }

    if caplen > MAXIMUM_SNAPLEN {
        let msg = if caplen > p.snapshot as u32 {
            format!(
                "invalid packet capture length {}, bigger than snaplen of {}",
                caplen, p.snapshot
            )
        } else {
            format!(
                "invalid packet capture length {}, bigger than maximum of {}",
                caplen, MAXIMUM_SNAPLEN
            )
        };
        return NextResult::Err(msg);
    }

    if caplen > p.snapshot as u32 {
        if caplen as usize > p.bufsize && !grow_buffer(p, p.snapshot as usize) {
            return NextResult::Err(String::new());
        }
        let snap = p.snapshot as usize;
        let got = reader.read(snap);
        if got.len() != snap {
            let msg = format!(
                "truncated dump file; tried to read {} captured bytes, only got {}",
                p.snapshot,
                got.len()
            );
            return NextResult::Err(msg);
        }
        p.buffer[0..snap].copy_from_slice(&got);
        let mut bytes_to_discard = caplen as usize - snap;
        let mut bytes_read = got.len();
        while bytes_to_discard != 0 {
            let bytes_to_read = bytes_to_discard.min(4096);
            let d = reader.read(bytes_to_read);
            bytes_read += d.len();
            if d.len() != bytes_to_read {
                let msg = format!(
                    "truncated dump file; tried to read {} captured bytes, only got {}",
                    caplen, bytes_read
                );
                return NextResult::Err(msg);
            }
            bytes_to_discard -= d.len();
        }
        caplen = snap as u32;
    } else {
        if caplen as usize > p.bufsize {
            let mut new_bufsize = caplen;
            new_bufsize = new_bufsize.wrapping_sub(1);
            new_bufsize |= new_bufsize >> 1;
            new_bufsize |= new_bufsize >> 2;
            new_bufsize |= new_bufsize >> 4;
            new_bufsize |= new_bufsize >> 8;
            new_bufsize |= new_bufsize >> 16;
            new_bufsize = new_bufsize.wrapping_add(1);
            if new_bufsize > p.snapshot as u32 {
                new_bufsize = p.snapshot as u32;
            }
            if !grow_buffer(p, new_bufsize as usize) {
                return NextResult::Err(String::new());
            }
        }
        let got = reader.read(caplen as usize);
        if got.len() != caplen as usize {
            let msg = format!(
                "truncated dump file; tried to read {} captured bytes, only got {}",
                caplen,
                got.len()
            );
            return NextResult::Err(msg);
        }
        p.buffer[0..caplen as usize].copy_from_slice(&got);
    }

    NextResult::Packet {
        caplen,
        len,
        tv_sec: tv_sec_i64,
        tv_usec: tv_usec_i64,
    }
}
