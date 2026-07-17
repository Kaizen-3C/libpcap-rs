//! Assembles the shim + verbatim-sliced C reference for each differential fuzz target from the
//! upstream libpcap 1.10.5 tarball, the same way scripts/regen_goldens.sh does for the
//! op-script drivers, and compiles them into this fuzz crate with matching ASan
//! instrumentation so both sides of each differential contribute to libFuzzer's coverage
//! feedback. One build.rs invocation covers every `[[bin]]` in this package.
//!
//! Requires PCAP_SRC (the unpacked libpcap-1.10.5 tree) to be set — regen_goldens.sh's tarball
//! extraction (cref/_build/libpcap-1.10.5) works; run that once first if cref/_build is empty.

use std::path::Path;
use std::process::Command;

struct Target {
    /// cref/assemble_*.py to run
    assemble_script: &'static str,
    /// output C filename that script writes (relative to OUT_DIR)
    out_c_file: &'static str,
    /// extra cref/ files the assemble script reads, for cargo:rerun-if-changed
    extra_deps: &'static [&'static str],
    /// name passed to cc::Build::compile (must be unique per target)
    lib_name: &'static str,
}

const TARGETS: &[Target] = &[
    Target {
        assemble_script: "assemble_fuzzlib.py",
        out_c_file: "legacy_fuzzlib.c",
        extra_deps: &["_shim.h", "_fuzzlib_driver.c"],
        lib_name: "pcap_fuzzlib",
    },
    Target {
        assemble_script: "assemble_fuzzlib_pcapng.py",
        out_c_file: "legacy_fuzzlib_pcapng.c",
        extra_deps: &["_shim_pcapng.h", "_fuzzlib_driver_pcapng.c"],
        lib_name: "pcap_fuzzlib_pcapng",
    },
];

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

    for t in TARGETS {
        let status = Command::new("python3")
            .arg(cref.join(t.assemble_script))
            .env("PCAP_SRC", &pcap_src)
            .env("OUT", &out_dir)
            .status()
            .unwrap_or_else(|e| panic!("run cref/{} (needs python3 on PATH): {e}", t.assemble_script));
        assert!(status.success(), "{} failed", t.assemble_script);

        println!("cargo:rerun-if-changed={}", cref.join(t.assemble_script).display());
        for dep in t.extra_deps {
            println!("cargo:rerun-if-changed={}", cref.join(dep).display());
        }

        // fuzzer-no-link is a clang-only -fsanitize= value; the `cc` crate's default `cc` alias
        // may resolve to gcc, which rejects it, so force clang explicitly.
        cc::Build::new()
            .compiler("clang")
            .file(Path::new(&out_dir).join(t.out_c_file))
            .flag("-fsanitize=address,fuzzer-no-link")
            .flag("-g")
            .flag("-O1")
            .compile(t.lib_name);
    }
}
