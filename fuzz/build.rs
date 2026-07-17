//! Assembles cref/legacy_fuzzlib.c (shim + verbatim sf-pcap.c slice + the FFI wrapper) from the
//! upstream libpcap 1.10.5 tarball, the same way scripts/regen_goldens.sh does for the
//! op-script driver, and compiles it into this fuzz binary with matching ASan instrumentation
//! so both sides of the differential contribute to libFuzzer's coverage feedback.
//!
//! Requires PCAP_SRC (the unpacked libpcap-1.10.5 tree) to be set — regen_goldens.sh's tarball
//! extraction (cref/_build/libpcap-1.10.5) works; run that once first if cref/_build is empty.

use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_root = Path::new(&manifest_dir).parent().unwrap();
    let cref = crate_root.join("cref");
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let pcap_src = std::env::var("PCAP_SRC")
        .unwrap_or_else(|_| crate_root.join("cref/_build/libpcap-1.10.5").display().to_string());
    assert!(
        Path::new(&pcap_src).join("sf-pcap.c").is_file(),
        "PCAP_SRC ({pcap_src}) doesn't contain sf-pcap.c — run scripts/regen_goldens.sh once \
         first to extract the pinned tarball, or set PCAP_SRC explicitly"
    );

    let status = Command::new("python3")
        .arg(cref.join("assemble_fuzzlib.py"))
        .env("PCAP_SRC", &pcap_src)
        .env("OUT", &out_dir)
        .status()
        .expect("run cref/assemble_fuzzlib.py (needs python3 on PATH)");
    assert!(status.success(), "assemble_fuzzlib.py failed");

    println!("cargo:rerun-if-changed={}", cref.join("_shim.h").display());
    println!(
        "cargo:rerun-if-changed={}",
        cref.join("_fuzzlib_driver.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cref.join("assemble_fuzzlib.py").display()
    );

    // fuzzer-no-link is a clang-only -fsanitize= value; the `cc` crate's default `cc` alias may
    // resolve to gcc, which rejects it, so force clang explicitly.
    cc::Build::new()
        .compiler("clang")
        .file(Path::new(&out_dir).join("legacy_fuzzlib.c"))
        .flag("-fsanitize=address,fuzzer-no-link")
        .flag("-g")
        .flag("-O1")
        .compile("pcap_fuzzlib");
}
