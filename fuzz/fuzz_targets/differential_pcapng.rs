//! Differential fuzz target for the pcapng module: one raw byte string per run, parsed through
//! the Rust port's public pcapng API and through the verbatim-sliced C reference (via FFI,
//! cref/_fuzzlib_driver_pcapng.c), and the traces byte-compared. Mirrors
//! src/bin/differential_driver_pcapng.rs's per-case logic exactly, minus the hex/stdin layer.
//! See fuzz_targets/differential.rs for the classic-pcap sibling and the shared design notes.

#![no_main]

use std::fmt::Write as _;

use libfuzzer_sys::fuzz_target;
use libpcap_rs::pcapng::{pcap_ng_check_header, pcap_ng_next_packet, PcapPkthdr};

extern "C" {
    fn run_case_c_pcapng(data: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c_pcapng(p: *mut u8);
}

fn run_case_c_safe(data: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c_pcapng is the verbatim-sliced C reference (cref/_fuzzlib_driver_pcapng.c),
    // given a valid pointer+length and always returning either NULL or a buffer it allocated
    // itself sized `outlen`; we free it with the matching free_case_c_pcapng right after copying.
    unsafe {
        let ptr = run_case_c_pcapng(data.as_ptr(), data.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c_pcapng(ptr);
        s
    }
}

const PCAP_TSTAMP_PRECISION_MICRO: u32 = 0;

fn run_case_rust(data: &[u8]) -> String {
    let mut out = String::new();
    if data.len() < 4 {
        out.push_str("X not-pcapng\n.\n");
        return out;
    }

    let magic = [data[0], data[1], data[2], data[3]];
    let mut p = match pcap_ng_check_header(&magic, &data[4..], PCAP_TSTAMP_PRECISION_MICRO) {
        Ok(p) => p,
        Err(e) => {
            writeln!(out, "X {}", e).unwrap();
            out.push_str(".\n");
            return out;
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
        let mut hdr = PcapPkthdr {
            ts_sec: 0,
            ts_usec: 0,
            caplen: 0,
            len: 0,
        };
        match pcap_ng_next_packet(&mut p, &mut hdr) {
            Ok(data) => {
                let mut h: u32 = 2166136261;
                for byte in data {
                    h ^= byte as u32;
                    h = h.wrapping_mul(16777619);
                }
                writeln!(
                    out,
                    "P {} {} {} {} {:08x}",
                    hdr.caplen, hdr.len, hdr.ts_sec, hdr.ts_usec, h
                )
                .unwrap();
                npkt += 1;
            }
            Err(0) => break,
            Err(_) => {
                writeln!(out, "E {}", p.errbuf).unwrap();
                break;
            }
        }
    }
    writeln!(out, "Z {}", npkt).unwrap();
    out.push_str(".\n");
    out
}

fuzz_target!(|data: &[u8]| {
    let c_trace = run_case_c_safe(data);
    let rust_trace = run_case_rust(data);
    assert_eq!(
        c_trace, rust_trace,
        "pcapng differential mismatch on input {:?}",
        data
    );
});
