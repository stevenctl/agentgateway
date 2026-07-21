## Session Affinity Example

This example shows how to pin a client's session to a single backend endpoint using
the `loadBalancing.consistentHash` policy, and how to **hand-roll the session cookie**
that affinity keys on using a `transformations` policy plus the CEL `random()` function.

Consistent hashing needs a stable value to hash on. A session cookie is the usual
choice, but the client only sends it once the gateway (or an upstream) has set it. This
example closes that loop entirely in config: the response transform mints a random `sid`
cookie on the first request, and every request thereafter is hashed on it.

> A future Gateway API `sessionPersistence` policy will provide managed cookie/TTL
> semantics out of the box. This example is how you can do it today.

### Running the example

Start three upstream servers, each reporting its own port:

```bash
for p in 8081 8082 8083; do
  python3 -c "
import http.server,sys
port=int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(f'backend:{port}\n'.encode())
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',port),H).serve_forever()" "$p" &
done
```

Start agentgateway:

```bash
cargo run -- -f examples/traffic-session-affinity/config.yaml
```

The config defines one Service (`echo`) with three endpoints (`127.0.0.1:8081-8083`).

### Trying it out

The first request has no `sid` cookie, so the gateway mints one:

```bash
curl -i http://localhost:3000/
# ...
# set-cookie: sid=0.1319...; Path=/; HttpOnly
# backend:8081
```

Send that cookie back and every request pins to the same endpoint:

```bash
curl -s -b "sid=0.1319..." http://localhost:3000/   # backend:8081
curl -s -b "sid=0.1319..." http://localhost:3000/   # backend:8081
curl -s -b "sid=0.1319..." http://localhost:3000/   # backend:8081
```

Different cookie values distribute across the three endpoints, each one sticky:

```bash
for s in alpha bravo charlie delta; do curl -s -b "sid=$s" http://localhost:3000/; done
# backend:8083
# backend:8081
# backend:8083
# backend:8082
```

Requests with no cookie are not hashed at all; they fall back to the default
power-of-two-choices load balancer.

### How it works

Two backend policies compose on the route:

```yaml
policies:
  # Hash each request onto the endpoint ring by its sid cookie.
  loadBalancing:
    consistentHash:
      key: request.headers.cookie("sid")
  # Mint the cookie on the first response so there is something to hash on.
  transformations:
    response:
      add:
        set-cookie: >-
          ("cookie" in request.headers && request.headers["cookie"].contains("sid="))
          ? null
          : "sid=" + string(random()) + "; Path=/; HttpOnly"
```

- `consistentHash.key` is a CEL expression. `request.headers.cookie("sid")` reads the
  cookie value; when the cookie is absent the expression yields no value and the request
  falls back to the default algorithm (so the very first request is load-balanced
  normally, then pinned once it has a cookie).
- The response transform's value is a CEL ternary. When the request already carries a
  `sid` cookie the expression is `null`, so no `Set-Cookie` is emitted; otherwise it mints
  `sid=<random>`. `random()` returns a float in `[0, 1]`, which is plenty of entropy for
  distributing across a ring — concatenate a couple of calls if you want a longer id.

### Caveats

- On the "cookie already present" branch the transform evaluates to `null`, which makes
  agentgateway **remove** any `Set-Cookie` on that response. For the affinity cookie this
  is harmless (repeat requests carry no `Set-Cookie` to remove), but it would strip a
  `Set-Cookie` that the upstream itself set on that same response.
- The endpoint a session pins to is determined by hashing the (random) cookie value, not
  by which endpoint served the first request — subsequent requests are consistent, which
  is what session affinity needs.
