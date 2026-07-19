#!/usr/bin/env bash
# TRUE big-endian differential: build BOTH the verbatim-C reference and the Rust port for s390x
# (64-bit big-endian) and byte-compare their LIVE outputs under qemu-s390x.
#
# Why this exists (libpcap#1702): the earlier big-endian CI step ran only the Rust driver on s390x
# and compared it to a golden generated on little-endian x86. Because the port decodes fields
# host-independently, it matched that little-endian golden on ANY host, so the step could never
# reveal a host-RELATIVE bug — e.g. post_process's pseudo-header swap, which must convert to the
# reading host's byte order. Comparing the C reference and the port *both running on s390x* is the
# only check that actually exercises the big-endian reading-host path.
#
# Needs: gcc-s390x-linux-gnu (C cross-compiler + sysroot) and qemu-user-static, and the Rust
# s390x-unknown-linux-gnu target. regen_goldens.sh must have run first (it assembles legacy*.c from
# the pinned tarball into cref/_build).
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=cref/_build
S390X_CC="${S390X_CC:-s390x-linux-gnu-gcc}"
QEMU="${QEMU:-qemu-s390x-static}"
QEMU_L="${QEMU_L:-/usr/s390x-linux-gnu}"

[ -f "$BUILD/legacy.c" ] || { echo "run scripts/regen_goldens.sh first (need $BUILD/legacy.c)"; exit 1; }

echo "== cross-compiling the verbatim-C references for s390x"
"$S390X_CC" -O2 -o "$BUILD/cref_driver_s390x"        "$BUILD/legacy.c"
"$S390X_CC" -O2 -o "$BUILD/cref_driver_pcapng_s390x" "$BUILD/legacy_pcapng.c"

echo "== cross-building the Rust drivers for s390x"
CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER="$S390X_CC" \
  cargo build --release --quiet --target s390x-unknown-linux-gnu \
    --bin differential_driver --bin differential_driver_pcapng

fail=0
diff_one() {
  local name="$1" c_bin="$2" rs_bin="$3" inp="$4"
  "$QEMU" -L "$QEMU_L" "$c_bin"  < "$inp" | tr -d '\r' > "$BUILD/be_${name}_c.out"
  "$QEMU" -L "$QEMU_L" "$rs_bin" < "$inp" | tr -d '\r' > "$BUILD/be_${name}_rs.out"
  if cmp -s "$BUILD/be_${name}_c.out" "$BUILD/be_${name}_rs.out"; then
    echo "OK  $name: verbatim C == Rust port, BOTH on s390x ($(wc -l < "$inp") cases)"
  else
    echo "FAIL $name: verbatim C != Rust port on s390x (big-endian host divergence)"
    diff "$BUILD/be_${name}_c.out" "$BUILD/be_${name}_rs.out" | head -20 || true
    fail=1
  fi
}

RS=target/s390x-unknown-linux-gnu/release
diff_one pcap   "$BUILD/cref_driver_s390x"        "$RS/differential_driver"        tests/vectors/pcap_inputs.txt
diff_one pcapng "$BUILD/cref_driver_pcapng_s390x" "$RS/differential_driver_pcapng" tests/vectors/pcapng_inputs.txt
exit $fail
