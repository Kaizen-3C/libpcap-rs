//! Differential certification replay: drives the crate's op-script driver over the full
//! savefile-parser envelope and byte-compares against golden output produced by the upstream
//! libpcap 1.10.5 C reference build (see README.md / HARNESS.md for provenance).

use std::io::Write;
use std::process::{Command, Stdio};

fn run_driver(input: &str) -> String {
    let exe = env!("CARGO_BIN_EXE_differential_driver");
    let mut child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn differential_driver");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait driver");
    assert!(out.status.success(), "driver exited nonzero");
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[test]
fn pcap_envelope_matches_c_reference() {
    let got = normalize(&run_driver(include_str!("vectors/pcap_inputs.txt")));
    let want = normalize(include_str!("vectors/pcap_golden.txt"));
    if got != want {
        let (mut gl, mut wl) = (got.lines(), want.lines());
        let mut n = 0usize;
        loop {
            match (gl.next(), wl.next()) {
                (Some(a), Some(b)) if a == b => n += 1,
                (a, b) => panic!("first divergence at output line {n}: golden={b:?} got={a:?}"),
            }
        }
    }
}
