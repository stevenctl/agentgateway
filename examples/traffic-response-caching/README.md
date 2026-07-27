## Response Caching Example

This example shows agentgateway caching upstream responses based on their `Cache-Control`
headers, following RFC 9111. Cached responses are served without contacting the upstream.

### Running the example

Start the example upstream. It stamps every response with a request counter and a
`Cache-Control: max-age=10` header, so you can tell a cache hit from an origin fetch:

```bash
python3 examples/traffic-response-caching/upstream.py
```

Start agentgateway:

```bash
cargo run -- -f examples/traffic-response-caching/config.yaml
```

### Seeing the cache work

Send the same request a few times within 10 seconds:

```bash
curl -i http://localhost:3000/
curl -i http://localhost:3000/
```

The first request is a **miss**: it reaches the upstream, so the body shows a fresh
request number. The second is a **hit**: the body is identical (the counter did not
advance) and the response carries an `Age` header counting the seconds since it was cached.

Wait more than 10 seconds and try again — the entry has expired, so the request goes back
to the upstream and the counter advances.

The `/slow` route makes this obvious: the upstream sleeps 2s, so the first request is slow
and every cached hit returns instantly:

```bash
time curl -s http://localhost:3000/slow  # ~2s (miss)
time curl -s http://localhost:3000/slow  # instant (hit)
```

The `/no-store` route sets `Cache-Control: no-store`, so it is never cached — the counter
advances on every request.

### How it is configured

```yaml
policies:
  responseCache:
    # Freshness for responses that declare none: a duration, or a CEL expression on the response.
    ttl: 'response.code == 200 ? duration("10s") : duration("0s")'
```

`ttl` only fills the gap when the upstream declares no freshness of its own — a response with
`Cache-Control: max-age` always honors it. A zero or absent `ttl` result leaves the response
uncached, so the expression above also serves as "never cache non-200s."

`Vary` is honored automatically: a response with `Vary: Accept-Encoding` is stored as separate
variants per encoding, with no configuration. `Vary: *` responses are never cached.

Only safe methods (`GET`, `HEAD`) and cacheable status codes are stored, `private` and
`no-store` responses are never cached, and responses carrying `Set-Cookie` or requiring
`Authorization` are skipped unless the upstream explicitly marks them `public`.

### Sharing the cache across replicas

The default store is in-memory and local to each gateway instance. To share cached
responses across replicas, point the policy at Redis (see the commented block in
`config.yaml`):

```yaml
policies:
  responseCache:
    store:
      redis:
        host: localhost:6379
        db: 0
        keyPrefix: "agw:"
        operationTimeout: 500ms
```

The server is named the same way as any other backend — `host`, a `name`/`port` service
reference, or `backend` pointing at a top-level Backend — so the connection is made through
the gateway's own connector and backend policies apply to it. TLS, for example, is configured
rather than implied by a URL scheme:

```yaml
      redis:
        host: redis.example.com:6380
        password:
          file: /etc/redis/password
        policies:
          backendTLS:
            root: /etc/certs/redis-ca.pem
```

If Redis is unreachable, the cache fails open: requests fall through to the upstream
rather than erroring.
