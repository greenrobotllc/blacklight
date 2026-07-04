#!/usr/bin/env python3
"""A deliberately malicious HTTP proxy — the man-in-the-middle for the demo.

It forwards GET requests to an upstream origin but, for the target artifact,
flips one byte at a configurable offset as the bytes stream through. This is
exactly the tampering-in-transit that blacklight is designed to catch: the
origin is honest, the network is not.

Everything else (the manifest, the .obao tree, the Sigstore bundle) is passed
through untouched, modelling an attacker who can rewrite payload bytes but
cannot forge the publisher's signature over the manifest.

Standard library only. Python 3.8+.

    python3 evil_proxy.py --listen 8081 --origin http://127.0.0.1:8080 \\
        --target /demo.bin --offset 5000000
"""

import argparse
import http.server
import sys
import urllib.request

ARGS = None


class MitmHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):  # keep the demo output readable
        sys.stderr.write("[evil_proxy] " + (fmt % a) + "\n")

    def do_GET(self):
        upstream = ARGS.origin.rstrip("/") + self.path
        tamper = self.path == ARGS.target
        # Once the status line + headers are on the wire we can no longer send an
        # HTTP error response — doing so would emit a second status line into the
        # same response. After that point, failures are logged and the
        # connection is simply dropped.
        headers_sent = False
        try:
            with urllib.request.urlopen(upstream, timeout=30) as resp:
                body_len = resp.headers.get("Content-Length")
                self.send_response(resp.status)
                # Force plain streaming: known length, no transfer-encoding games.
                for k, v in resp.headers.items():
                    if k.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(k, v)
                if body_len is not None:
                    self.send_header("Content-Length", body_len)
                self.send_header("Connection", "close")
                self.end_headers()
                headers_sent = True

                if tamper:
                    sys.stderr.write(
                        f"[evil_proxy] TAMPERING with {self.path}: "
                        f"flipping byte at offset {ARGS.offset}\n"
                    )

                pos = 0
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    if tamper and pos <= ARGS.offset < pos + len(chunk):
                        i = ARGS.offset - pos
                        chunk = bytearray(chunk)
                        chunk[i] ^= 0xFF  # flip every bit of one byte
                        chunk = bytes(chunk)
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        # The client aborted mid-stream — for blacklight under
                        # attack, this is the whole point.
                        sys.stderr.write(
                            f"[evil_proxy] client hung up after ~{pos + len(chunk)} bytes "
                            "(verified-streaming client aborting early)\n"
                        )
                        return
                    pos += len(chunk)
        except Exception as e:  # noqa: BLE001 - demo tool, surface anything
            if headers_sent:
                # A 200 response is already in flight; we can't turn it into an
                # error. Log and let the connection close.
                sys.stderr.write(f"[evil_proxy] upstream error mid-stream: {e}\n")
            else:
                self.send_error(502, f"upstream error: {e}")


def main():
    global ARGS
    p = argparse.ArgumentParser(description="Tampering MITM proxy for the blacklight demo")
    p.add_argument("--listen", type=int, default=8081)
    p.add_argument("--origin", default="http://127.0.0.1:8080")
    p.add_argument("--target", default="/demo.bin",
                   help="path to tamper with; everything else passes through")
    p.add_argument("--offset", type=int, default=5_000_000,
                   help="byte offset within the target to corrupt")
    ARGS = p.parse_args()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", ARGS.listen), MitmHandler)
    sys.stderr.write(
        f"[evil_proxy] listening on :{ARGS.listen}, forwarding to {ARGS.origin}, "
        f"tampering {ARGS.target}@{ARGS.offset}\n"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
