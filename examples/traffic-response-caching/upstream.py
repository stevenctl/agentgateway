#!/usr/bin/env python3
"""A tiny upstream for the response-caching example.

Every response body carries a request counter and the time it was generated, and the
server declares `Cache-Control: max-age=10`. When agentgateway serves a request from its
cache the body stays identical (the counter does not advance) and an `Age` header appears,
so you can see caching at work.

Routes:
  /            cacheable: Cache-Control: max-age=10
  /no-store    not cacheable: Cache-Control: no-store
  /slow        cacheable but sleeps 2s, to make cache hits obviously faster
"""

import time
from http.server import BaseHTTPRequestHandler, HTTPServer

count = 0


class Handler(BaseHTTPRequestHandler):
    def _send(self, cache_control, delay=0.0):
        global count
        if delay:
            time.sleep(delay)
        count += 1
        body = f"request #{count} generated at {time.strftime('%H:%M:%S')}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", cache_control)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/no-store"):
            self._send("no-store")
        elif self.path.startswith("/slow"):
            self._send("max-age=10", delay=2.0)
        else:
            self._send("max-age=10")

    def log_message(self, *args):
        pass  # keep the terminal quiet; the interesting output is on the client


if __name__ == "__main__":
    print("upstream listening on http://127.0.0.1:8080")
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
