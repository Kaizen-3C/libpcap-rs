//! Differential op-script driver: one hex-encoded classic-pcap file per stdin line,
//! parsed through the public API; prints a deterministic trace byte-compared against the
//! upstream C reference (mirrors cref/_driver.c), including verbatim error strings.

use std::io::{self, BufRead, Write};

use libpcap_rs::{pcap_check_header, pcap_next_packet, FileSim, NextResult};

fn hexval(c: u8) -> i32 {
    match c {
        b'0'..=b'9' => (c - b'0') as i32,
        b'a'..=b'f' => (c - b'a' + 10) as i32,
        b'A'..=b'F' => (c - b'A' + 10) as i32,
        _ => -1,
    }
}

fn decode_line(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let c0 = if 2 * i < line.len() { line[2 * i] } else { 0 };
        let c1 = if 2 * i + 1 < line.len() {
            line[2 * i + 1]
        } else {
            0
        };
        if c0 == 0 || c1 == 0 {
            break;
        }
        let hi = hexval(c0);
        let lo = hexval(c1);
        if hi < 0 || lo < 0 {
            break;
        }
        if out.len() >= (1usize << 20) {
            break;
        }
        out.push(((hi << 4) | lo) as u8);
        i += 1;
    }
    out
}

fn read_fgets_line<R: BufRead>(reader: &mut R, max_len: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let limit = max_len - 1;
    loop {
        if buf.len() >= limit {
            break;
        }
        let available = match reader.fill_buf() {
            Ok(a) => a,
            Err(_) => break,
        };
        if available.is_empty() {
            break;
        }
        let remaining_capacity = limit - buf.len();
        let take = available.len().min(remaining_capacity);
        if let Some(pos) = available[..take].iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        } else {
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            if take == 0 {
                break;
            }
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

fn main() {
    let stdin = io::stdin();
    let mut reader = io::BufReader::with_capacity(1 << 16, stdin.lock());
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    const MAX_LINE: usize = 2 * (1 << 20) + 4;

    while let Some(line) = read_fgets_line(&mut reader, MAX_LINE) {
        let filedata = decode_line(&line);

        if filedata.len() < 4 {
            writeln!(out, "X not-pcap").unwrap();
            writeln!(out, ".").unwrap();
            continue;
        }

        let magic = [filedata[0], filedata[1], filedata[2], filedata[3]];
        let mut fsim = FileSim {
            data: &filedata,
            pos: 4,
        };

        let (popt, errbuf) = pcap_check_header(magic, &mut fsim);
        let mut p = match popt {
            Some(pp) => pp,
            None => {
                let msg = if errbuf.is_empty() {
                    "not-pcap".to_string()
                } else {
                    errbuf
                };
                writeln!(out, "X {}", msg).unwrap();
                writeln!(out, ".").unwrap();
                continue;
            }
        };

        writeln!(
            out,
            "H {} {} {} {} {}",
            p.version_major, p.version_minor, p.swapped as i32, p.linktype, p.snapshot
        )
        .unwrap();

        let mut npkt = 0i32;
        loop {
            match pcap_next_packet(&mut p, &mut fsim) {
                NextResult::Eof => break,
                NextResult::Err(msg) => {
                    writeln!(out, "E {}", msg).unwrap();
                    break;
                }
                NextResult::Packet {
                    caplen,
                    len,
                    tv_sec,
                    tv_usec,
                } => {
                    let mut h: u32 = 2166136261;
                    for k in 0..caplen as usize {
                        h ^= p.buffer[k] as u32;
                        h = h.wrapping_mul(16777619);
                    }
                    writeln!(out, "P {} {} {} {} {:08x}", caplen, len, tv_sec, tv_usec, h).unwrap();
                    npkt += 1;
                }
            }
        }
        writeln!(out, "Z {}", npkt).unwrap();
        writeln!(out, ".").unwrap();
    }
}
