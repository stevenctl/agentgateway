//! HTTP response caching, following RFC 9111.
//!
//! The cache is driven by the upstream's `Cache-Control`/`Expires` headers: a response is stored
//! when it declares its own freshness, and the freshness/age arithmetic follows RFC 9111 sections
//! 4.2.1-4.2.3. When a response declares no freshness, the optional `ttl` expression supplies a
//! default (see [`ResponseCache::ttl`]).
//!
//! `Vary` is honored automatically (RFC 9111 4.1): a response that varies on request headers is
//! stored as a separate variant keyed on those headers, with no configuration. `Vary: *` responses
//! are never stored.
//!
//! This is a shared (proxy) cache, so `s-maxage` overrides `max-age` and `private` responses are
//! never stored.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ::http::{HeaderMap, HeaderName, StatusCode, header};
use bytes::Bytes;

use crate::cel::{self, Expression, RequestSnapshot};
use crate::http::{Body, Request, Response};
use crate::proxy::httpproxy::PolicyClient;
use crate::*;

mod redis_store;
mod storage;

pub use redis_store::{RedisConfig, RedisStorage};
pub use storage::{CacheStorage, InMemoryStorage};

#[cfg(test)]
#[path = "responsecache_tests.rs"]
mod responsecache_tests;

pub const DEFAULT_MAX_ENTRIES: usize = 1024;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Upper bound on stored variants per resource, to cap growth from many `Vary` combinations.
const MAX_VARIANTS: usize = 16;

/// Connection-specific headers that must not be stored or replayed (RFC 9110 7.6.1).
const HOP_BY_HOP: &[&str] = &[
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
];

#[apply(schema!)]
pub struct ResponseCache {
	/// Where cached responses are kept.
	#[serde(default)]
	pub store: StoreConfig,
	/// Largest response body to cache, in bytes. Larger responses stream through uncached.
	#[serde(default = "default_max_body_bytes")]
	pub max_body_bytes: usize,
	/// Freshness applied when a response declares none (no `max-age`/`s-maxage`/`Expires`). Either a
	/// duration such as `30s`, or a CEL expression evaluated against the response that returns a
	/// duration, e.g. `response.code == 200 ? duration("5m") : duration("0s")`. A zero or absent
	/// result leaves the response uncached. Responses that declare their own freshness always honor
	/// it; this only fills the gap.
	#[serde(
		default,
		deserialize_with = "cel::de_opt_duration_or_expression",
		skip_serializing_if = "Option::is_none"
	)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub ttl: Option<Arc<Expression>>,
	#[serde(skip, default = "default_storage")]
	storage: Arc<dyn CacheStorage>,
}

/// Backing store for cache entries.
#[apply(schema!)]
pub enum StoreConfig {
	/// Keep entries in this gateway instance's memory. Entries are not shared between replicas, so
	/// each instance warms its own cache.
	InMemory(InMemoryConfig),
	/// Keep entries in Redis, shared across every gateway instance pointed at the same server.
	Redis(RedisConfig),
}

impl Default for StoreConfig {
	fn default() -> Self {
		StoreConfig::InMemory(InMemoryConfig::default())
	}
}

#[apply(schema!)]
#[derive(Default)]
pub struct InMemoryConfig {
	/// Maximum number of resources to keep. Least-recently-used entries are evicted.
	#[serde(default = "default_max_entries")]
	pub max_entries: usize,
}

fn default_max_entries() -> usize {
	DEFAULT_MAX_ENTRIES
}

fn default_max_body_bytes() -> usize {
	DEFAULT_MAX_BODY_BYTES
}

fn default_storage() -> Arc<dyn CacheStorage> {
	Arc::new(InMemoryStorage::new(DEFAULT_MAX_ENTRIES))
}

impl crate::store::HasExpressions for ResponseCache {
	fn expressions(&self) -> impl Iterator<Item = &Expression> {
		self.ttl.as_deref().into_iter()
	}
}

impl ResponseCache {
	/// Builds a policy from explicit parts and sizes its store. Used by XDS translation, where the
	/// config arrives as proto fields rather than through serde.
	pub fn from_parts(
		store: StoreConfig,
		max_body_bytes: Option<usize>,
		ttl: Option<Arc<Expression>>,
	) -> anyhow::Result<Self> {
		Self {
			store,
			max_body_bytes: max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
			ttl,
			storage: default_storage(),
		}
		.with_configured_store()
	}

	/// Builds the backing store from the deserialized config. Must be called after deserialization,
	/// since the store itself is not part of the config.
	pub fn with_configured_store(mut self) -> anyhow::Result<Self> {
		self.storage = match &self.store {
			StoreConfig::InMemory(cfg) => Arc::new(InMemoryStorage::new(cfg.max_entries.max(1))),
			StoreConfig::Redis(cfg) => Arc::new(RedisStorage::new(cfg)?),
		};
		Ok(self)
	}

	/// Looks up `req`, returning the action the proxy should take.
	pub async fn lookup(&self, client: &PolicyClient, req: &mut Request) -> Lookup {
		// Everything read from the request happens up front, before the store is awaited: a shared
		// `&Request` is not `Send`.
		let Some((key, may_serve, pending)) = self.prepare_lookup(req) else {
			return Lookup::Bypass;
		};
		if may_serve {
			// Fail-open lives here, once, for every backend: a store that errors degrades to an origin
			// fetch rather than failing the request.
			match self.storage.get(client, &key).await {
				Ok(Some(entry)) => {
					let now = SystemTime::now();
					if let Some(variant) = entry.select(&pending.request_headers, now) {
						return Lookup::Hit(variant.response.to_response(now));
					}
				},
				Ok(None) => {},
				Err(e) => debug!(error = %e, "cache lookup failed; falling through to origin"),
			}
		}
		Lookup::Miss(pending)
	}

	/// Decides whether `req` participates in caching, and under what key.
	fn prepare_lookup(&self, req: &Request) -> Option<(CacheKey, bool, PendingStore)> {
		if !is_cacheable_method(req.method()) {
			return None;
		}
		let directives = Directives::parse(req.headers());
		// `no-store` means we may neither serve nor record this exchange.
		if directives.no_store {
			return None;
		}
		let key = cache_key(req);
		let pending = PendingStore {
			key: key.clone(),
			request_time: SystemTime::now(),
			request_headers: req.headers().clone(),
			has_authorization: req.headers().contains_key(header::AUTHORIZATION),
		};
		// `no-cache` forces us to go to the origin, but the result may still be stored.
		Some((key, !directives.no_cache, pending))
	}

	/// Stores `resp` if RFC 9111 allows it. Returns whether the response was stored.
	///
	/// `request_snapshot` provides request context to the `ttl` expression. The body is peeked
	/// rather than drained, so a response too large to cache still streams to the client untouched.
	pub async fn store_response(
		&self,
		client: &PolicyClient,
		pending: &PendingStore,
		resp: &mut Response,
		request_snapshot: Option<&RequestSnapshot>,
	) -> bool {
		if !is_cacheable_status(resp.status()) {
			return false;
		}
		let headers = resp.headers();
		let directives = Directives::parse(headers);
		if directives.no_store || directives.private {
			return false;
		}
		// A shared cache must not reuse an authorized response unless the origin opts in
		// (RFC 9111 3.5).
		if pending.has_authorization && !directives.allows_authorized_reuse() {
			return false;
		}
		// Storing credentials in a shared cache is rarely intended; skip rather than guess.
		if headers.contains_key(header::SET_COOKIE) {
			return false;
		}
		// Vary: * can never be matched, so it is never cacheable (RFC 9111 4.1).
		let Some(vary) = parse_vary(headers) else {
			return false;
		};

		let response_time = SystemTime::now();
		// Freshness declared by the origin always wins; the `ttl` default only fills the gap.
		let lifetime = match protocol_freshness(headers, response_time) {
			ProtocolFreshness::Forbidden => return false,
			ProtocolFreshness::Declared(d) => d,
			ProtocolFreshness::Undeclared => match self.eval_ttl(resp, request_snapshot) {
				Some(d) if d > Duration::ZERO => d,
				_ => return false,
			},
		};
		let age = response_age(
			resp.headers(),
			pending.request_time,
			response_time,
			lifetime,
		);
		if age >= lifetime {
			return false;
		}

		let status = resp.status();
		let stored_headers = storable_headers(resp.headers());
		let body =
			match crate::http::inspect_body_with_limit(resp.body_mut(), self.max_body_bytes).await {
				Ok(crate::http::BodyInspection::Complete(b)) => b,
				// Partial means the body exceeded max_body_bytes; caching it would truncate the entry.
				Ok(crate::http::BodyInspection::Partial(_)) => {
					debug!(limit = self.max_body_bytes, "response too large to cache");
					return false;
				},
				Err(e) => {
					warn!(error = %e, "failed to read response body for caching");
					return false;
				},
			};

		let stored = StoredResponse {
			status,
			headers: stored_headers,
			body,
			response_time,
			initial_age: age,
			lifetime,
		};
		// The request's values for the varied headers form this variant's secondary key.
		let secondary: Vec<String> = vary
			.iter()
			.map(|h| header_value(&pending.request_headers, h))
			.collect();

		// Read-modify-write the resource's entry so other variants survive.
		let mut entry = match self.storage.get(client, &pending.key).await {
			Ok(Some(e)) => e,
			Ok(None) => CacheEntry::default(),
			Err(e) => {
				debug!(error = %e, "cache read-before-write failed; starting a fresh entry");
				CacheEntry::default()
			},
		};
		// If the resource now varies on a different header set, its old variants are unusable.
		if entry.vary != vary {
			entry = CacheEntry {
				vary: vary.clone(),
				variants: Vec::new(),
			};
		}
		let now = SystemTime::now();
		// Drop stale variants and any prior variant with the same secondary key.
		entry
			.variants
			.retain(|v| v.secondary != secondary && v.response.is_fresh(now));
		entry.variants.push(Variant {
			secondary,
			response: stored,
		});
		// Bound growth from pathological Vary combinations.
		while entry.variants.len() > MAX_VARIANTS {
			entry.variants.remove(0);
		}

		if let Err(e) = self.storage.insert(client, &pending.key, entry).await {
			debug!(error = %e, "failed to store response in cache");
			return false;
		}
		true
	}

	/// Evaluates the `ttl` default expression against the response, returning a duration if it yields
	/// one. Runs before the body is captured, so `response.body` is not available to it.
	fn eval_ttl(
		&self,
		resp: &Response,
		request_snapshot: Option<&RequestSnapshot>,
	) -> Option<Duration> {
		let expr = self.ttl.as_ref()?;
		let exec = cel::Executor::new_response(request_snapshot, resp);
		match exec.eval(expr) {
			Ok(cel::Value::Duration(d)) => d.to_std().ok(),
			Ok(_) => None,
			Err(e) => {
				debug!(error = %e, "response cache ttl expression failed");
				None
			},
		}
	}
}

/// What the request phase decided to do.
pub enum Lookup {
	/// Serve this response without contacting the upstream.
	Hit(Response),
	/// Forward upstream; the response may be stored under this key.
	Miss(PendingStore),
	/// Not cacheable at all; forward and do not store.
	Bypass,
}

/// Per-request state carried from the request phase to the response phase.
#[derive(Debug, Clone)]
pub struct PendingStore {
	key: CacheKey,
	/// When the request was sent, for the age correction in RFC 9111 4.2.3.
	request_time: SystemTime,
	/// Kept so the varied-header values can be read once the response's `Vary` is known.
	request_headers: HeaderMap,
	has_authorization: bool,
}

/// Primary cache key: the request identity (RFC 9111 4.1). Variance is handled separately, per
/// entry, from the response's `Vary` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
	method: String,
	scheme: String,
	authority: String,
	path: String,
}

impl CacheKey {
	/// Stable textual form, for stores that key on strings.
	pub fn to_storage_key(&self) -> String {
		format!(
			"{} {}://{}{}",
			self.method, self.scheme, self.authority, self.path
		)
	}
}

/// All cached variants of one resource, sharing a primary key.
#[derive(Debug, Clone, Default)]
pub struct CacheEntry {
	/// Request-header names the responses vary on (lowercase, sorted). Empty means no variance.
	pub vary: Vec<String>,
	pub variants: Vec<Variant>,
}

impl CacheEntry {
	/// Returns the fresh variant matching `req_headers`, if any.
	fn select(&self, req_headers: &HeaderMap, now: SystemTime) -> Option<&Variant> {
		let secondary: Vec<String> = self
			.vary
			.iter()
			.map(|h| header_value(req_headers, h))
			.collect();
		self
			.variants
			.iter()
			.find(|v| v.secondary == secondary && v.response.is_fresh(now))
	}

	/// Whether any variant is still fresh (used by stores to evict dead entries).
	pub fn any_fresh(&self, now: SystemTime) -> bool {
		self.variants.iter().any(|v| v.response.is_fresh(now))
	}

	/// The longest remaining freshness across variants, for store-side expiry.
	pub fn max_remaining_ttl(&self, now: SystemTime) -> Duration {
		self
			.variants
			.iter()
			.map(|v| v.response.remaining_ttl(now))
			.max()
			.unwrap_or(Duration::ZERO)
	}
}

/// One stored variant: the request-header values that select it, plus the response.
#[derive(Debug, Clone)]
pub struct Variant {
	pub secondary: Vec<String>,
	pub response: StoredResponse,
}

/// A stored response, plus the timing needed to age it (RFC 9111 4.2.3).
#[derive(Debug, Clone)]
pub struct StoredResponse {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: Bytes,
	/// When the response was received. Wall clock, so entries remain meaningful across instances.
	pub response_time: SystemTime,
	/// Age at the moment it was received (RFC 9111 corrected_initial_age).
	pub initial_age: Duration,
	/// Total freshness lifetime the response was granted.
	pub lifetime: Duration,
}

impl StoredResponse {
	/// current_age = corrected_initial_age + resident_time (RFC 9111 4.2.3).
	pub fn current_age(&self, now: SystemTime) -> Duration {
		let resident = now
			.duration_since(self.response_time)
			.unwrap_or(Duration::ZERO);
		self.initial_age + resident
	}

	pub fn is_fresh(&self, now: SystemTime) -> bool {
		self.current_age(now) < self.lifetime
	}

	/// Remaining freshness, for stores that expire entries themselves.
	pub fn remaining_ttl(&self, now: SystemTime) -> Duration {
		self.lifetime.saturating_sub(self.current_age(now))
	}

	fn to_response(&self, now: SystemTime) -> Response {
		let mut resp = ::http::Response::new(Body::from(self.body.clone()));
		*resp.status_mut() = self.status;
		*resp.headers_mut() = self.headers.clone();
		let age = self.current_age(now).as_secs();
		if let Ok(value) = ::http::HeaderValue::from_str(&age.to_string()) {
			resp.headers_mut().insert(header::AGE, value);
		}
		resp
	}
}

/// Builds the primary cache key (RFC 9111 4.1).
fn cache_key(req: &Request) -> CacheKey {
	let uri = req.uri();
	let authority = uri
		.authority()
		.map(|a| a.as_str().to_string())
		.or_else(|| {
			req
				.headers()
				.get(header::HOST)
				.and_then(|h| h.to_str().ok())
				.map(str::to_string)
		})
		.unwrap_or_default();
	CacheKey {
		method: req.method().as_str().to_string(),
		scheme: uri.scheme_str().unwrap_or("http").to_string(),
		authority,
		path: uri
			.path_and_query()
			.map(|p| p.as_str().to_string())
			.unwrap_or_else(|| uri.path().to_string()),
	}
}

/// Parses the response `Vary` header into sorted, deduped, lowercase field names. Returns `None`
/// when `Vary: *` is present, which makes the response uncacheable (RFC 9111 4.1).
fn parse_vary(headers: &HeaderMap) -> Option<Vec<String>> {
	let mut names = Vec::new();
	for value in headers.get_all(header::VARY) {
		let Ok(value) = value.to_str() else {
			return None;
		};
		for field in value.split(',') {
			let field = field.trim().to_lowercase();
			if field.is_empty() {
				continue;
			}
			if field == "*" {
				return None;
			}
			names.push(field);
		}
	}
	names.sort();
	names.dedup();
	Some(names)
}

/// The value of `name` in `headers`, empty when absent. Multiple values are joined so a variant is
/// selected consistently.
fn header_value(headers: &HeaderMap, name: &str) -> String {
	let mut parts = headers
		.get_all(name)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.peekable();
	if parts.peek().is_none() {
		return String::new();
	}
	parts.collect::<Vec<_>>().join(",")
}

/// Strips headers that must not be replayed from a cache entry.
fn storable_headers(headers: &HeaderMap) -> HeaderMap {
	// Headers named by `Connection` are also connection-specific.
	let mut connection_named: Vec<String> = Vec::new();
	for value in headers.get_all(header::CONNECTION) {
		if let Ok(value) = value.to_str() {
			connection_named.extend(value.split(',').map(|v| v.trim().to_lowercase()));
		}
	}
	let mut out = HeaderMap::new();
	for (name, value) in headers {
		let lower = name.as_str();
		if HOP_BY_HOP.contains(&lower) || connection_named.iter().any(|c| c == lower) {
			continue;
		}
		// Age is recomputed per hit.
		if name == header::AGE {
			continue;
		}
		out.append(name.clone(), value.clone());
	}
	out
}

/// Only safe methods are cacheable. POST is cacheable in principle but requires
/// `Content-Location` matching that is not worth the footgun here.
fn is_cacheable_method(method: &::http::Method) -> bool {
	matches!(*method, ::http::Method::GET | ::http::Method::HEAD)
}

/// Status codes a cache may reuse (RFC 9110 15.1). 206 is excluded: partial content needs range
/// handling we do not do.
fn is_cacheable_status(status: StatusCode) -> bool {
	matches!(
		status.as_u16(),
		200 | 203 | 204 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 421 | 451 | 501
	)
}

/// The `Cache-Control` directives that affect storage decisions.
#[derive(Debug, Default, Clone, Copy)]
struct Directives {
	no_store: bool,
	no_cache: bool,
	private: bool,
	public: bool,
	must_revalidate: bool,
	has_s_maxage: bool,
}

impl Directives {
	fn parse(headers: &HeaderMap) -> Self {
		let mut out = Self::default();
		for (name, value) in cache_control_directives(headers) {
			match name.as_str() {
				"no-store" => out.no_store = true,
				"no-cache" => out.no_cache = true,
				"private" => out.private = true,
				"public" => out.public = true,
				"must-revalidate" => out.must_revalidate = true,
				"s-maxage" => out.has_s_maxage = !value.is_empty(),
				_ => {},
			}
		}
		out
	}

	/// RFC 9111 3.5: a shared cache may reuse an authorized response only when the origin says so.
	fn allows_authorized_reuse(&self) -> bool {
		self.public || self.must_revalidate || self.has_s_maxage
	}
}

/// Cache-Control directives may be split across header lines, so they are joined before parsing
/// (RFC 9110 5.3).
fn cache_control_directives(headers: &HeaderMap) -> Vec<(String, String)> {
	let mut out = Vec::new();
	for value in headers.get_all(header::CACHE_CONTROL) {
		let Ok(value) = value.to_str() else { continue };
		for directive in value.split(',') {
			let directive = directive.trim();
			if directive.is_empty() {
				continue;
			}
			let (name, value) = match directive.split_once('=') {
				Some((n, v)) => (n, v),
				None => (directive, ""),
			};
			out.push((
				name.trim().to_lowercase(),
				value.trim().trim_matches('"').to_string(),
			));
		}
	}
	out
}

/// Freshness the origin declared for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolFreshness {
	/// The origin forbids caching (`no-store`/`no-cache`/zero or malformed max-age).
	Forbidden,
	/// The origin granted this much freshness.
	Declared(Duration),
	/// The origin said nothing; a default may apply.
	Undeclared,
}

/// Computes the freshness the response declared via `Cache-Control`/`Expires` (RFC 9111 4.2.1). For
/// a shared cache `s-maxage` takes precedence over `max-age` (RFC 9111 5.2.2.10). A malformed
/// `max-age` forbids caching rather than falling through to a default, so a broken origin never gets
/// a longer lifetime than it asked for.
fn protocol_freshness(headers: &HeaderMap, response_time: SystemTime) -> ProtocolFreshness {
	let mut max_age = None;
	let mut saw_max_age = false;
	let mut valid_max_age = false;
	let mut s_maxage = None;

	for (name, value) in cache_control_directives(headers) {
		match name.as_str() {
			// Without revalidation support, both mean "do not reuse".
			"no-store" | "no-cache" => return ProtocolFreshness::Forbidden,
			"s-maxage" => {
				let Ok(seconds) = value.parse::<u64>() else {
					continue;
				};
				if seconds == 0 {
					return ProtocolFreshness::Forbidden;
				}
				if s_maxage.is_none() {
					s_maxage = Some(Duration::from_secs(seconds));
				}
			},
			"max-age" => {
				saw_max_age = true;
				if valid_max_age {
					continue;
				}
				let Ok(seconds) = value.parse::<u64>() else {
					continue;
				};
				if seconds == 0 {
					return ProtocolFreshness::Forbidden;
				}
				max_age = Some(Duration::from_secs(seconds));
				valid_max_age = true;
			},
			_ => {},
		}
	}

	if let Some(s) = s_maxage {
		return ProtocolFreshness::Declared(s);
	}
	if let Some(m) = max_age {
		return ProtocolFreshness::Declared(m);
	}
	if saw_max_age {
		// Present but unparseable.
		return ProtocolFreshness::Forbidden;
	}
	match expires_lifetime(headers, response_time) {
		Some(d) => ProtocolFreshness::Declared(d),
		None => ProtocolFreshness::Undeclared,
	}
}

/// Freshness implied by `Expires` relative to `Date` (RFC 9111 4.2.1).
fn expires_lifetime(headers: &HeaderMap, response_time: SystemTime) -> Option<Duration> {
	let expires = header_date(headers, header::EXPIRES)?;
	let base = header_date(headers, header::DATE).unwrap_or(response_time);
	expires.duration_since(base).ok()
}

/// corrected_initial_age, clamped to `limit` (RFC 9111 4.2.3).
fn response_age(
	headers: &HeaderMap,
	request_time: SystemTime,
	response_time: SystemTime,
	limit: Duration,
) -> Duration {
	let mut corrected = response_time
		.duration_since(request_time)
		.unwrap_or_default()
		.min(limit);
	if let Some(seconds) = headers
		.get(header::AGE)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.trim().parse::<u64>().ok())
	{
		corrected = if seconds >= limit.as_secs() {
			limit
		} else {
			(corrected + Duration::from_secs(seconds)).min(limit)
		};
	}

	let apparent = header_date(headers, header::DATE)
		.and_then(|date| response_time.duration_since(date).ok())
		.unwrap_or_default();

	apparent.max(corrected).min(limit)
}

fn header_date(headers: &HeaderMap, name: HeaderName) -> Option<SystemTime> {
	headers
		.get(name)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| httpdate::parse_http_date(v).ok())
}
