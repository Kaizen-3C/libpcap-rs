//! Differential fuzz target: one raw byte string per run, parsed through the Rust port's
//! public API and through the verbatim-sliced C reference (via FFI, cref/_fuzzlib_driver.c),
//! and the traces byte-compared. A mismatch — or a Rust panic — is a libFuzzer crash with a
//! minimized repro. Mirrors src/bin/differential_driver.rs's per-case logic exactly, minus the
//! hex/stdin layer (the fuzzer already hands us raw bytes in-process).

#![no_main]

use std::fmt::Write as _;

use libfuzzer_sys::fuzz_target;
use libpcap_rs::{pcap_check_header, pcap_next_packet, FileSim, NextResult};

extern "C" {
    fn run_case_c(data: *const u8, n: usize, outlen: *mut usize) -> *mut u8;
    fn free_case_c(p: *mut u8);
}

fn run_case_c_safe(data: &[u8]) -> String {
    let mut outlen: usize = 0;
    // SAFETY: run_case_c is the verbatim-sliced C reference (cref/_fuzzlib_driver.c), given a
    // valid pointer+length and always returning either NULL or a buffer it allocated itself
    // sized `outlen`; we free it with the matching free_case_c right after copying it out.
    unsafe {
        let ptr = run_case_c(data.as_ptr(), data.len(), &mut outlen as *mut usize);
        if ptr.is_null() {
            return String::new();
        }
        let bytes = std::slice::from_raw_parts(ptr, outlen);
        let s = String::from_utf8_lossy(bytes).into_owned();
        free_case_c(ptr);
        s
    }
}

fn run_case_rust(data: &[u8]) -> String {
    let mut out = String::new();
    if data.len() < 4 {
        out.push_str("X not-pcap\n.\n");
        return out;
    }

    let magic = [data[0], data[1], data[2], data[3]];
    let mut fsim = FileSim { data, pos: 4 };

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
    out.push_str(".\n");
    out
}

fuzz_target!(|data: &[u8]| {
    let c_trace = run_case_c_safe(data);
    let rust_trace = run_case_rust(data);
    assert_eq!(
        c_trace, rust_trace,
        "pcap differential mismatch on input {:?}",
        data
    );
});
