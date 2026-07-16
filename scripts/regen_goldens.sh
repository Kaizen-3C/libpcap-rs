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

echo "== compiling C reference ($CC)"
"$CC" -O2 -D_CRT_SECURE_NO_WARNINGS -o "$BUILD/cref_driver" "$BUILD/legacy.c"

echo "== building Rust driver"
cargo build --release --quiet
RUST_DRV=target/release/differential_driver
[ -x "$RUST_DRV" ] || RUST_DRV=target/release/differential_driver.exe

fail=0
inp=tests/vectors/pcap_inputs.txt
gold=tests/vectors/pcap_golden.txt
"$BUILD/cref_driver" < "$inp" | tr -d '\r' > "$BUILD/pcap_c.out"
"$RUST_DRV"          < "$inp" | tr -d '\r' > "$BUILD/pcap_rs.out"
tr -d '\r' < "$gold" > "$BUILD/pcap_gold.norm"
if cmp -s "$BUILD/pcap_c.out" "$BUILD/pcap_rs.out"; then
  echo "OK  pcap: upstream-built C == Rust ($(wc -l < "$inp") cases)"
else
  echo "FAIL pcap: upstream-built C != Rust"; fail=1
fi
if cmp -s "$BUILD/pcap_c.out" "$BUILD/pcap_gold.norm"; then
  echo "OK  pcap: upstream-built C == checked-in golden"
else
  echo "FAIL pcap: upstream-built C != checked-in golden"; fail=1
fi
exit $fail
