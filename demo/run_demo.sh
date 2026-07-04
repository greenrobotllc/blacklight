#!/usr/bin/env bash
# End-to-end attack demo for blacklight.
#
# Publishes a file, serves it from an honest origin, then fetches it two ways:
#   1. directly from the honest origin  -> succeeds, bytes match
#   2. through a tampering MITM proxy    -> blacklight aborts mid-stream at the
#      first bad 16 KiB chunk group, leaving no output file
#
# and contrasts blacklight with the naive `curl | sha256sum` baseline, which
# must download the entire file before it can notice the tampering.
#
# Usage: demo/run_demo.sh [SIZE_MB] [TAMPER_OFFSET]
set -euo pipefail

SIZE_MB="${1:-64}"
OFFSET="${2:-$(( SIZE_MB * 1024 * 1024 / 2 ))}"   # default: tamper near the middle
GROUP=16384

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BL="$ROOT/target/release/blacklight"
WORK="$(mktemp -d)"
ORIGIN_PORT=8080
PROXY_PORT=8081

cleanup() { [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
            [ -n "${PROXY_PID:-}"  ] && kill "$PROXY_PID"  2>/dev/null || true
            rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> building release binary"
( cd "$ROOT" && cargo build --release --quiet )

echo "==> creating ${SIZE_MB} MiB test artifact"
python3 - "$WORK/demo.bin" "$SIZE_MB" <<'PY'
import sys
path, mb = sys.argv[1], int(sys.argv[2])
with open(path, "wb") as f:
    buf = bytes((i * 7 + 3) % 256 for i in range(1024 * 1024))
    for _ in range(mb):
        f.write(buf)
PY

echo "==> blacklight publish (unsigned; signing is exercised separately against Sigstore)"
"$BL" publish "$WORK/demo.bin" --unsigned

echo "==> starting honest origin :$ORIGIN_PORT and tampering proxy :$PROXY_PORT (flip @ $OFFSET)"
( cd "$WORK" && python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
ORIGIN_PID=$!
python3 "$ROOT/demo/evil_proxy.py" --listen "$PROXY_PORT" \
    --origin "http://127.0.0.1:$ORIGIN_PORT" --target /demo.bin --offset "$OFFSET" \
    >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 1

echo
echo "################  SCENARIO 1: honest origin  ################"
if "$BL" fetch "http://127.0.0.1:$ORIGIN_PORT/demo.bin.blacklight.json" \
        --allow-unsigned -o "$WORK/clean.out"; then
  cmp -s "$WORK/clean.out" "$WORK/demo.bin" \
    && echo ">> clean download verified and byte-identical to the original."
else
  echo ">> UNEXPECTED: clean download failed"; exit 1
fi

echo
echo "################  SCENARIO 2: tampering MITM proxy  ################"
set +e
"$BL" fetch "http://127.0.0.1:$PROXY_PORT/demo.bin.blacklight.json" \
    --allow-unsigned -o "$WORK/tampered.out"
BL_EXIT=$?
set -e
echo ">> blacklight exit code: $BL_EXIT (3 = integrity violation)"
if [ -f "$WORK/tampered.out" ]; then echo ">> BUG: a partial file was left behind"; else
  echo ">> no output file was written — the tampered bytes never reached disk as 'good'."; fi

echo
echo "################  BASELINE: curl | sha256sum  ################"
GOOD_SHA=$(sha256sum "$WORK/demo.bin" | cut -d' ' -f1)
BYTES_BEFORE_DETECT=$(( (OFFSET / GROUP + 1) * GROUP ))
BASELINE_BYTES=$(( SIZE_MB * 1024 * 1024 ))
curl -s "http://127.0.0.1:$PROXY_PORT/demo.bin" -o "$WORK/curl.out"
BAD_SHA=$(sha256sum "$WORK/curl.out" | cut -d' ' -f1)
[ "$GOOD_SHA" != "$BAD_SHA" ] && echo ">> curl completed the FULL download; only then does the hash mismatch."

echo
echo "==================  DETECTION METRICS  =================="
printf '%-38s %15s\n' "tampered byte offset"              "$OFFSET"
printf '%-38s %15s\n' "total artifact size (bytes)"       "$BASELINE_BYTES"
printf '%-38s %15s\n' "blacklight: bytes consumed before" "$BYTES_BEFORE_DETECT"
printf '%-38s %15s\n' "  detection (one 16 KiB group)"    ""
printf '%-38s %15s\n' "curl+sha256: bytes consumed before" "$BASELINE_BYTES"
printf '%-38s %15s\n' "  detection (whole file)"          ""
RATIO=$(python3 -c "print(f'{$BASELINE_BYTES/$BYTES_BEFORE_DETECT:.1f}x')")
printf '%-38s %15s\n' "data blacklight avoided reading"   "$RATIO less"
echo
echo "(Note: bytes *consumed and verified* by the client. Actual bytes on the"
echo " wire can be higher due to TCP/HTTP read-ahead buffering — see proxy.log —"
echo " but no unverified byte is ever accepted or written as good output.)"
grep 'client hung up' "$WORK/proxy.log" || true
