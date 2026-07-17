#!/usr/bin/env bash
# Rebuild the C reference from the UPSTREAM libpcap 1.10.5 tarball and verify the differential
# from first principles:
#   1. download libpcap-1.10.5.tar.gz (or use $PCAP_TARBALL), pin sha256
#   2. cref/assemble.py slices the VERBATIM savefile-parser bodies (pcap_check_header,
#      grow_buffer, pcap_next_packet + the pcap_sf structs/enums) from src/sf-pcap.c and
#      stitches them with cref/_shim.h (the minimal pcap_t + helpers those functions need,
#      plus a tmpfile-backed FILE*) and cref/_driver.c (the op-script driver)
#   3. compile, run over tests/vectors/pcap_inputs.txt, byte-compare against the Rust
#      differential_driver and the checked-in golden.
# Exits nonzero on any mismatch.
set -euo pipefail
cd "$(dirname "$0")/.."

SHA=37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0
URL=https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz
BUILD=cref/_build
CC="${CC:-clang}"
mkdir -p "$BUILD"

TARBALL="${PCAP_TARBALL:-$BUILD/libpcap-1.10.5.tar.gz}"
if [ ! -f "$TARBALL" ]; then
  echo "== downloading $URL"
  curl -sSL -o "$TARBALL" "$URL"
fi
echo "$SHA  $TARBALL" | sha256sum -c -

cp "$TARBALL" "$BUILD/_pcap.tgz"
tar xzf "$BUILD/_pcap.tgz" -C "$BUILD"
UP="$BUILD/libpcap-1.10.5"

echo "== assembling legacy.c from upstream sf-pcap.c (verbatim parser + shim + driver)"
PCAP_SRC="$UP" OUT="$BUILD" python cref/assemble.py

echo "== assembling legacy_pcapng.c from upstream sf-pcapng.c (verbatim parser + shim + driver)"
PCAP_SRC="$UP" OUT="$BUILD" python cref/assemble_pcapng.py

echo "== compiling C references ($CC)"
"$CC" -O2 -D_CRT_SECURE_NO_WARNINGS -o "$BUILD/cref_driver" "$BUILD/legacy.c"
"$CC" -O2 -D_CRT_SECURE_NO_WARNINGS -o "$BUILD/cref_driver_pcapng" "$BUILD/legacy_pcapng.c"

echo "== building Rust drivers"
cargo build --release --quiet
RUST_DRV=target/release/differential_driver
[ -x "$RUST_DRV" ] || RUST_DRV=target/release/differential_driver.exe
RUST_DRV_NG=target/release/differential_driver_pcapng
[ -x "$RUST_DRV_NG" ] || RUST_DRV_NG=target/release/differential_driver_pcapng.exe

fail=0
check() {
  local name="$1" c_driver="$2" rs_driver="$3" inp="$4" gold="$5"
  "$c_driver"  < "$inp" | tr -d '\r' > "$BUILD/${name}_c.out"
  "$rs_driver" < "$inp" | tr -d '\r' > "$BUILD/${name}_rs.out"
  tr -d '\r' < "$gold" > "$BUILD/${name}_gold.norm"
  if cmp -s "$BUILD/${name}_c.out" "$BUILD/${name}_rs.out"; then
    echo "OK  $name: upstream-built C == Rust ($(wc -l < "$inp") cases)"
  else
    echo "FAIL $name: upstream-built C != Rust"; fail=1
  fi
  if cmp -s "$BUILD/${name}_c.out" "$BUILD/${name}_gold.norm"; then
    echo "OK  $name: upstream-built C == checked-in golden"
  else
    echo "FAIL $name: upstream-built C != checked-in golden"; fail=1
  fi
}

check pcap   "$BUILD/cref_driver"        "$RUST_DRV"    tests/vectors/pcap_inputs.txt      tests/vectors/pcap_golden.txt
check pcapng "$BUILD/cref_driver_pcapng" "$RUST_DRV_NG" tests/vectors/pcapng_inputs.txt    tests/vectors/pcapng_golden.txt
exit $fail
