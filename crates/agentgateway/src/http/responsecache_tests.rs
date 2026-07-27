use std::time::{Duration, SystemTime};

use ::http::{HeaderMap, HeaderValue, StatusCode, header};

use super::*;

const T0: SystemTime = SystemTime::UNIX_EPOCH;

fn now() -> SystemTime {
	T0 + Duration::from_secs(1_700_000_000)
}

/// Only a remote store connects through this; the in-memory store these tests use ignores it.
fn client() -> PolicyClient {
	crate::test_helpers::policy_client()
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
	let mut h = HeaderMap::new();
	for (k, v) in pairs {
		h.append(
			HeaderName::from_bytes(k.as_bytes()).unwrap(),
			HeaderValue::from_str(v).unwrap(),
		);
	}
	h
}

// ---- protocol freshness (RFC 9111 4.2.1) ----

fn declared(cc: &[(&str, &str)]) -> Option<Duration> {
	match protocol_freshness(&headers(cc), now()) {
		ProtocolFreshness::Declared(d) => Some(d),
		_ => None,
	}
}

#[test]
fn max_age_is_declared_freshness() {
	assert_eq!(
		declared(&[("cache-control", "max-age=30")]),
		Some(Duration::from_secs(30))
	);
}

#[test]
fn no_store_and_no_cache_forbid_caching() {
	for cc in ["no-store", "no-cache", "max-age=60, no-store"] {
		assert_eq!(
			protocol_freshness(&headers(&[("cache-control", cc)]), now()),
			ProtocolFreshness::Forbidden,
			"{cc}"
		);
	}
}

#[test]
fn zero_and_malformed_max_age_forbid_caching() {
	assert_eq!(
		protocol_freshness(&headers(&[("cache-control", "max-age=0")]), now()),
		ProtocolFreshness::Forbidden
	);
	// Malformed max-age must not silently fall through to the default slot.
	assert_eq!(
		protocol_freshness(&headers(&[("cache-control", "max-age=abc")]), now()),
		ProtocolFreshness::Forbidden
	);
}

#[test]
fn no_cache_control_is_undeclared() {
	assert_eq!(
		protocol_freshness(&HeaderMap::new(), now()),
		ProtocolFreshness::Undeclared
	);
}

/// A shared cache prefers s-maxage over max-age (RFC 9111 5.2.2.10).
#[test]
fn s_maxage_overrides_max_age() {
	assert_eq!(
		declared(&[("cache-control", "max-age=30, s-maxage=90")]),
		Some(Duration::from_secs(90))
	);
	assert_eq!(
		protocol_freshness(&headers(&[("cache-control", "s-maxage=0")]), now()),
		ProtocolFreshness::Forbidden
	);
}

#[test]
fn directives_may_span_multiple_header_lines() {
	assert_eq!(
		declared(&[("cache-control", "public"), ("cache-control", "max-age=30")]),
		Some(Duration::from_secs(30))
	);
	// no-store on a later line still forbids.
	assert_eq!(
		protocol_freshness(
			&headers(&[
				("cache-control", "max-age=30"),
				("cache-control", "no-store")
			]),
			now()
		),
		ProtocolFreshness::Forbidden
	);
}

#[test]
fn expires_provides_freshness_without_max_age() {
	let h = headers(&[
		("date", &httpdate::fmt_http_date(now())),
		(
			"expires",
			&httpdate::fmt_http_date(now() + Duration::from_secs(120)),
		),
	]);
	assert_eq!(
		protocol_freshness(&h, now()),
		ProtocolFreshness::Declared(Duration::from_secs(120))
	);
}

#[test]
fn max_age_takes_precedence_over_expires() {
	let h = headers(&[
		("cache-control", "max-age=30"),
		("date", &httpdate::fmt_http_date(now())),
		(
			"expires",
			&httpdate::fmt_http_date(now() + Duration::from_secs(9999)),
		),
	]);
	assert_eq!(declared_of(&h), Some(Duration::from_secs(30)));
}

fn declared_of(h: &HeaderMap) -> Option<Duration> {
	match protocol_freshness(h, now()) {
		ProtocolFreshness::Declared(d) => Some(d),
		_ => None,
	}
}

// ---- age (RFC 9111 4.2.3) ----

#[test]
fn age_header_counts_against_freshness() {
	let age = response_age(
		&headers(&[("age", "40")]),
		now(),
		now(),
		Duration::from_secs(100),
	);
	assert_eq!(age, Duration::from_secs(40));
}

#[test]
fn in_flight_time_counts_as_age() {
	let sent = now();
	let received = sent + Duration::from_secs(5);
	let age = response_age(&HeaderMap::new(), sent, received, Duration::from_secs(30));
	assert_eq!(age, Duration::from_secs(5));
}

#[test]
fn date_header_produces_apparent_age() {
	let received = now();
	let generated = received - Duration::from_secs(20);
	let h = headers(&[("date", &httpdate::fmt_http_date(generated))]);
	let age = response_age(&h, received, received, Duration::from_secs(60));
	assert_eq!(age, Duration::from_secs(20));
}

// ---- storability primitives ----

#[test]
fn only_safe_methods_are_cacheable() {
	assert!(is_cacheable_method(&::http::Method::GET));
	assert!(is_cacheable_method(&::http::Method::HEAD));
	assert!(!is_cacheable_method(&::http::Method::POST));
}

#[test]
fn cacheable_statuses_exclude_partial_and_server_errors() {
	assert!(is_cacheable_status(StatusCode::OK));
	assert!(is_cacheable_status(StatusCode::NOT_FOUND));
	assert!(!is_cacheable_status(StatusCode::PARTIAL_CONTENT));
	assert!(!is_cacheable_status(StatusCode::INTERNAL_SERVER_ERROR));
}

#[test]
fn hop_by_hop_headers_are_not_stored() {
	let h = headers(&[
		("content-type", "application/json"),
		("connection", "x-custom"),
		("transfer-encoding", "chunked"),
		("x-custom", "drop me"),
		("age", "7"),
	]);
	let stored = storable_headers(&h);
	assert!(stored.contains_key(header::CONTENT_TYPE));
	assert!(!stored.contains_key(header::CONNECTION));
	assert!(!stored.contains_key(header::TRANSFER_ENCODING));
	assert!(!stored.contains_key("x-custom")); // named by Connection
	assert!(!stored.contains_key(header::AGE)); // recomputed per hit
}

#[test]
fn authorized_responses_need_explicit_opt_in() {
	assert!(
		!Directives::parse(&headers(&[("cache-control", "max-age=60")])).allows_authorized_reuse()
	);
	for cc in ["public", "must-revalidate", "s-maxage=60"] {
		assert!(
			Directives::parse(&headers(&[("cache-control", cc)])).allows_authorized_reuse(),
			"{cc}"
		);
	}
}

// ---- Vary parsing ----

#[test]
fn vary_parses_names_and_rejects_wildcard() {
	assert_eq!(parse_vary(&HeaderMap::new()), Some(vec![]));
	assert_eq!(
		parse_vary(&headers(&[("vary", "Accept-Encoding")])),
		Some(vec!["accept-encoding".to_string()])
	);
	// Sorted + deduped across lines.
	assert_eq!(
		parse_vary(&headers(&[
			("vary", "Accept-Language, Accept-Encoding"),
			("vary", "accept-encoding")
		])),
		Some(vec![
			"accept-encoding".to_string(),
			"accept-language".to_string()
		])
	);
	// Wildcard is uncacheable.
	assert_eq!(parse_vary(&headers(&[("vary", "*")])), None);
}

// ---- cache key ----

fn get(uri: &str) -> Request {
	::http::Request::builder()
		.method(::http::Method::GET)
		.uri(uri)
		.body(Body::empty())
		.unwrap()
}

#[test]
fn cache_key_is_request_identity_only() {
	assert_eq!(
		cache_key(&get("http://example.com/a")),
		cache_key(&get("http://example.com/a"))
	);
	assert_ne!(
		cache_key(&get("http://example.com/a")),
		cache_key(&get("http://example.com/b"))
	);
	assert_ne!(
		cache_key(&get("http://example.com/a?x=1")),
		cache_key(&get("http://example.com/a?x=2"))
	);
	// The key no longer depends on headers — Vary handles that per entry.
	let mut with_header = get("http://example.com/a");
	with_header
		.headers_mut()
		.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
	assert_eq!(
		cache_key(&with_header),
		cache_key(&get("http://example.com/a"))
	);
}

// ---- integration ----

fn cache_with(ttl: Option<&str>) -> ResponseCache {
	ResponseCache {
		store: StoreConfig::InMemory(InMemoryConfig { max_entries: 16 }),
		max_body_bytes: 1024,
		ttl: ttl.map(|t| crate::cel::compile_duration_or_expression(t).unwrap()),
		storage: default_storage(),
	}
	.with_configured_store()
	.unwrap()
}

fn cache() -> ResponseCache {
	cache_with(None)
}

fn response(status: StatusCode, pairs: &[(&str, &str)], body: &str) -> Response {
	let mut resp = ::http::Response::new(Body::from(body.to_string()));
	*resp.status_mut() = status;
	*resp.headers_mut() = headers(pairs);
	resp
}

async fn body_string(resp: &mut Response) -> String {
	let body = std::mem::replace(resp.body_mut(), Body::empty());
	let bytes = crate::http::read_body_with_limit(body, 64 * 1024)
		.await
		.unwrap();
	String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn miss_then_hit_serves_stored_response() {
	let c = cache();
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("first lookup should miss");
	};
	let mut resp = response(
		StatusCode::OK,
		&[
			("cache-control", "max-age=30"),
			("content-type", "text/plain"),
		],
		"hello",
	);
	assert!(c.store_response(&client(), &pending, &mut resp, None).await);
	assert_eq!(body_string(&mut resp).await, "hello"); // client still gets it

	let Lookup::Hit(mut hit) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("second lookup should hit");
	};
	assert_eq!(
		hit.headers().get(header::CONTENT_TYPE).unwrap(),
		"text/plain"
	);
	assert!(hit.headers().contains_key(header::AGE));
	assert_eq!(body_string(&mut hit).await, "hello");
}

#[tokio::test]
async fn ttl_default_applies_only_when_response_declares_none() {
	// With a default ttl, a response with no Cache-Control is cached.
	let c = cache_with(Some("30s"));
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("miss");
	};
	let mut resp = response(StatusCode::OK, &[], "hi");
	assert!(c.store_response(&client(), &pending, &mut resp, None).await);
	assert!(matches!(
		c.lookup(&client(), &mut get("http://example.com/a")).await,
		Lookup::Hit(_)
	));

	// Without a default ttl, the same response is not cached.
	let c = cache();
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/b")).await else {
		panic!("miss");
	};
	let mut resp = response(StatusCode::OK, &[], "hi");
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
}

#[tokio::test]
async fn origin_freshness_wins_over_ttl_default() {
	// ttl default would be 1s, but the origin says 60s — origin wins.
	let c = cache_with(Some("1s"));
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("miss");
	};
	let mut resp = response(StatusCode::OK, &[("cache-control", "max-age=60")], "x");
	assert!(c.store_response(&client(), &pending, &mut resp, None).await);
	// A hit right away confirms it was stored with the origin's (longer) lifetime.
	assert!(matches!(
		c.lookup(&client(), &mut get("http://example.com/a")).await,
		Lookup::Hit(_)
	));
}

/// A CEL ttl can branch on the response — here, never cache 5xx even if a default is set.
#[tokio::test]
async fn cel_ttl_can_refuse_by_returning_zero() {
	let c = cache_with(Some(
		"response.code >= 500 ? duration(\"0s\") : duration(\"30s\")",
	));

	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/ok")).await else {
		panic!("miss");
	};
	let mut ok = response(StatusCode::OK, &[], "good");
	assert!(c.store_response(&client(), &pending, &mut ok, None).await);

	let Lookup::Miss(pending) = c
		.lookup(&client(), &mut get("http://example.com/err"))
		.await
	else {
		panic!("miss");
	};
	// 501 is a cacheable status, but the ttl expression returns 0 for it.
	let mut err = response(StatusCode::NOT_IMPLEMENTED, &[], "bad");
	assert!(!c.store_response(&client(), &pending, &mut err, None).await);
}

/// Vary is honored automatically: variants are split by the varied header, with no config.
#[tokio::test]
async fn vary_splits_variants_automatically() {
	let c = cache();

	let mut gzip_req = get("http://example.com/a");
	gzip_req
		.headers_mut()
		.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
	let Lookup::Miss(gzip_pending) = c.lookup(&client(), &mut gzip_req).await else {
		panic!("miss");
	};
	let mut gzip_resp = response(
		StatusCode::OK,
		&[("cache-control", "max-age=60"), ("vary", "accept-encoding")],
		"GZIPPED",
	);
	assert!(
		c.store_response(&client(), &gzip_pending, &mut gzip_resp, None)
			.await
	);

	// A request with a different Accept-Encoding is a MISS, not a wrong hit.
	let mut br_req = get("http://example.com/a");
	br_req
		.headers_mut()
		.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br"));
	let Lookup::Miss(br_pending) = c.lookup(&client(), &mut br_req).await else {
		panic!("different Accept-Encoding must not hit the gzip variant");
	};
	let mut br_resp = response(
		StatusCode::OK,
		&[("cache-control", "max-age=60"), ("vary", "accept-encoding")],
		"BROTLI",
	);
	assert!(
		c.store_response(&client(), &br_pending, &mut br_resp, None)
			.await
	);

	// Now each Accept-Encoding gets its own stored body.
	let mut gzip_req2 = get("http://example.com/a");
	gzip_req2
		.headers_mut()
		.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
	let Lookup::Hit(mut hit) = c.lookup(&client(), &mut gzip_req2).await else {
		panic!("gzip should hit");
	};
	assert_eq!(body_string(&mut hit).await, "GZIPPED");

	let mut br_req2 = get("http://example.com/a");
	br_req2
		.headers_mut()
		.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br"));
	let Lookup::Hit(mut hit) = c.lookup(&client(), &mut br_req2).await else {
		panic!("br should hit");
	};
	assert_eq!(body_string(&mut hit).await, "BROTLI");
}

#[tokio::test]
async fn vary_wildcard_is_never_cached() {
	let c = cache();
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("miss");
	};
	let mut resp = response(
		StatusCode::OK,
		&[("cache-control", "max-age=60"), ("vary", "*")],
		"x",
	);
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
}

#[tokio::test]
async fn uncacheable_responses_are_not_stored() {
	let c = cache();
	let mut req = get("http://example.com/a");
	let Lookup::Miss(pending) = c.lookup(&client(), &mut req).await else {
		panic!("miss");
	};
	for pairs in [
		vec![("cache-control", "no-store")],
		vec![("cache-control", "private, max-age=60")],
		vec![("cache-control", "max-age=60"), ("set-cookie", "a=b")],
	] {
		let mut resp = response(StatusCode::OK, &pairs, "x");
		assert!(
			!c.store_response(&client(), &pending, &mut resp, None).await,
			"{pairs:?}"
		);
	}
	// Uncacheable status.
	let mut resp = response(
		StatusCode::INTERNAL_SERVER_ERROR,
		&[("cache-control", "max-age=60")],
		"x",
	);
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
	assert!(matches!(
		c.lookup(&client(), &mut req).await,
		Lookup::Miss(_)
	));
}

#[tokio::test]
async fn oversized_bodies_are_not_cached_but_still_stream() {
	let mut c = cache();
	c.max_body_bytes = 4;
	let mut req = get("http://example.com/big");
	let Lookup::Miss(pending) = c.lookup(&client(), &mut req).await else {
		panic!("miss");
	};
	let mut resp = response(
		StatusCode::OK,
		&[("cache-control", "max-age=60")],
		"much longer than four",
	);
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
	assert_eq!(body_string(&mut resp).await, "much longer than four");
	assert!(matches!(
		c.lookup(&client(), &mut req).await,
		Lookup::Miss(_)
	));
}

#[tokio::test]
async fn request_no_store_bypasses_and_no_cache_skips_the_hit() {
	let c = cache();
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("miss");
	};
	let mut resp = response(StatusCode::OK, &[("cache-control", "max-age=30")], "hello");
	assert!(c.store_response(&client(), &pending, &mut resp, None).await);

	let mut no_store = get("http://example.com/a");
	no_store
		.headers_mut()
		.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
	assert!(matches!(
		c.lookup(&client(), &mut no_store).await,
		Lookup::Bypass
	));

	let mut no_cache = get("http://example.com/a");
	no_cache
		.headers_mut()
		.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
	assert!(matches!(
		c.lookup(&client(), &mut no_cache).await,
		Lookup::Miss(_)
	));

	assert!(matches!(
		c.lookup(&client(), &mut get("http://example.com/a")).await,
		Lookup::Hit(_)
	));
}

#[tokio::test]
async fn non_cacheable_methods_bypass() {
	let c = cache();
	let mut req = ::http::Request::builder()
		.method(::http::Method::POST)
		.uri("http://example.com/a")
		.body(Body::empty())
		.unwrap();
	assert!(matches!(
		c.lookup(&client(), &mut req).await,
		Lookup::Bypass
	));
}

#[tokio::test]
async fn authorized_requests_are_only_cached_when_permitted() {
	let c = cache();
	let mut req = get("http://example.com/private");
	req
		.headers_mut()
		.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
	let Lookup::Miss(pending) = c.lookup(&client(), &mut req).await else {
		panic!("miss");
	};
	let mut resp = response(StatusCode::OK, &[("cache-control", "max-age=60")], "secret");
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
	let mut resp = response(
		StatusCode::OK,
		&[("cache-control", "public, max-age=60")],
		"shared",
	);
	assert!(c.store_response(&client(), &pending, &mut resp, None).await);
}

// ---- storage abstraction ----

fn variant(lifetime: Duration, response_time: SystemTime) -> Variant {
	Variant {
		secondary: vec![],
		response: StoredResponse {
			status: StatusCode::OK,
			headers: HeaderMap::new(),
			body: bytes::Bytes::from_static(b"x"),
			response_time,
			initial_age: Duration::ZERO,
			lifetime,
		},
	}
}

fn entry(v: Variant) -> CacheEntry {
	CacheEntry {
		vary: vec![],
		variants: vec![v],
	}
}

#[test]
fn stored_response_ages_by_wall_clock() {
	let stored = now();
	let r = variant(Duration::from_secs(60), stored).response;
	assert!(r.is_fresh(stored));
	assert!(r.is_fresh(stored + Duration::from_secs(59)));
	assert!(!r.is_fresh(stored + Duration::from_secs(60)));
	assert_eq!(
		r.remaining_ttl(stored + Duration::from_secs(10)),
		Duration::from_secs(50)
	);
	assert_eq!(
		r.remaining_ttl(stored + Duration::from_secs(999)),
		Duration::ZERO
	);
}

#[tokio::test]
async fn in_memory_storage_round_trips_and_evicts_dead_entries() {
	let s = InMemoryStorage::new(4);
	let c = client();
	let key = cache_key(&get("http://example.com/a"));
	assert!(s.get(&c, &key).await.unwrap().is_none());

	s.insert(
		&c,
		&key,
		entry(variant(Duration::from_secs(60), SystemTime::now())),
	)
	.await
	.unwrap();
	assert!(s.get(&c, &key).await.unwrap().is_some());

	// An entry whose only variant is already stale is dropped on read.
	s.insert(
		&c,
		&key,
		entry(variant(
			Duration::from_secs(5),
			SystemTime::now() - Duration::from_secs(60),
		)),
	)
	.await
	.unwrap();
	assert!(s.get(&c, &key).await.unwrap().is_none());
}

/// A backing store that fails every operation, to prove the consumer degrades rather than each
/// backend having to swallow errors itself.
#[derive(Debug)]
struct AlwaysFailingStorage;

#[async_trait::async_trait]
impl CacheStorage for AlwaysFailingStorage {
	async fn get(
		&self,
		_client: &PolicyClient,
		_key: &CacheKey,
	) -> anyhow::Result<Option<CacheEntry>> {
		anyhow::bail!("store down")
	}
	async fn insert(
		&self,
		_client: &PolicyClient,
		_key: &CacheKey,
		_value: CacheEntry,
	) -> anyhow::Result<()> {
		anyhow::bail!("store down")
	}
}

#[tokio::test]
async fn failing_store_degrades_to_origin() {
	let c = ResponseCache {
		store: StoreConfig::default(),
		max_body_bytes: 1024,
		ttl: None,
		storage: Arc::new(AlwaysFailingStorage),
	};
	let Lookup::Miss(pending) = c.lookup(&client(), &mut get("http://example.com/a")).await else {
		panic!("a failing store must degrade to a miss");
	};
	let mut resp = response(StatusCode::OK, &[("cache-control", "max-age=30")], "hello");
	assert!(!c.store_response(&client(), &pending, &mut resp, None).await);
	assert_eq!(body_string(&mut resp).await, "hello");
}

// ---- config surface ----

#[test]
fn config_parses_both_store_variants_and_ttl() {
	let c: ResponseCache = serde_json::from_str(r#"{"maxBodyBytes": 2048}"#).unwrap();
	assert!(matches!(c.store, StoreConfig::InMemory(_)));
	assert!(c.ttl.is_none());
	c.with_configured_store().unwrap();

	// Duration literal ttl.
	let c: ResponseCache = serde_json::from_str(r#"{"ttl": "30s"}"#).unwrap();
	assert!(c.ttl.is_some());

	// CEL ttl + redis store, built offline.
	let c: ResponseCache = serde_json::from_str(
		r#"{"store": {"redis": {"host": "cache:6379", "db": 1, "keyPrefix": "agw:"}}, "ttl": "response.code == 200 ? duration(\"5m\") : duration(\"0s\")"}"#,
	)
	.unwrap();
	assert!(matches!(c.store, StoreConfig::Redis(_)));
	assert!(c.ttl.is_some());
	c.with_configured_store().unwrap();
}
