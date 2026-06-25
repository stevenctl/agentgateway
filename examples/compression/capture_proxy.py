#!/usr/bin/env python3
"""Logging reverse-proxy: forwards to one upstream HTTPS host, tees req/resp bodies.

Used by run-terminal-bench.sh (CAPTURE=true) to record the gateway's UPSTREAM leg:

    container -> gateway:3000 -> 127.0.0.1:<port> (this proxy) -> https://<upstream>

So the captures are exactly what hits the model: post-compression for on/sim,
the true uncompressed baseline for off.

Usage: python3 capture_proxy.py <listen_port> <upstream_host> <label>
  e.g. python3 capture_proxy.py 8788 api.anthropic.com anthropic
       python3 capture_proxy.py 8799 api.openai.com openai

Captures land in $CAPTURE_DIR/<label>-<n>.{req,resp}.txt (default ./captures).
The full response is buffered (so SSE is reassembled) then returned with a
Content-Length. The gateway re-parses and re-streams it to the agent; the agent
sees each model turn at once rather than token-streamed, which is fine for bench.
"""
import http.server, http.client, ssl, sys, os, threading, itertools

PORT = int(sys.argv[1]); UPSTREAM = sys.argv[2]; LABEL = sys.argv[3]
OUT = os.environ.get("CAPTURE_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "captures")
os.makedirs(OUT, exist_ok=True)
_counter = itertools.count(1)
_lock = threading.Lock()

# headers we must not forward verbatim
HOP = {"host", "content-length", "connection", "accept-encoding",
       "transfer-encoding", "keep-alive", "proxy-connection"}

def redact(raw: bytes) -> bytes:
    # redact bearer/api keys in logged headers
    out = []
    for line in raw.split(b"\n"):
        low = line.lower()
        if low.startswith((b"authorization:", b"x-api-key:")):
            k = line.split(b":", 1)[0]
            out.append(k + b": <redacted>")
        else:
            out.append(line)
    return b"\n".join(out)

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _read_body(self) -> bytes:
        # The gateway forwards a known-length (Content-Length) body, but tolerate
        # chunked transfer-encoding too so we never silently drop a request body.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size_line = self.rfile.readline().split(b";", 1)[0].strip()
                n = int(size_line, 16)
                if n == 0:
                    self.rfile.readline()  # trailing CRLF
                    break
                chunks.append(self.rfile.read(n))
                self.rfile.read(2)  # CRLF after chunk
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _do(self):
        # Answer the startup readiness probe locally so it isn't forwarded
        # upstream (which 404s) or teed into the captures.
        if self.command == "GET" and self.path == "/":
            self.send_response(200); self.send_header("Content-Length", "2")
            self.end_headers(); self.wfile.write(b"ok"); return
        n = next(_counter)
        body = self._read_body()

        req_hdr = "".join(f"{k}: {v}\n" for k, v in self.headers.items()).encode()
        with open(os.path.join(OUT, f"{LABEL}-{n:03d}.req.txt"), "wb") as f:
            f.write(f"{self.command} {self.path}\n".encode())
            f.write(redact(req_hdr) + b"\n")
            f.write(body)

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(UPSTREAM, 443, context=ctx, timeout=600)
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        fwd["Host"] = UPSTREAM
        fwd["Accept-Encoding"] = "identity"  # readable bodies, no gzip
        try:
            conn.request(self.command, self.path, body=body, headers=fwd)
            resp = conn.getresponse()
            data = resp.read()
        except Exception as e:
            self.send_error(502, str(e)); return

        resp_hdr = "".join(f"{k}: {v}\n" for k, v in resp.getheaders()).encode()
        with open(os.path.join(OUT, f"{LABEL}-{n:03d}.resp.txt"), "wb") as f:
            f.write(f"HTTP {resp.status}\n".encode())
            f.write(resp_hdr + b"\n")
            f.write(data)

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in HOP: continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _do
    do_POST = _do

print(f"[{LABEL}] :{PORT} -> https://{UPSTREAM}  (captures in {OUT})", flush=True)
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
