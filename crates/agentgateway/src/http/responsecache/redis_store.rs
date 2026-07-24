//! Redis-backed shared cache store.
//!
//! Unlike the in-memory store, entries here are shared across every gateway instance pointed at the
//! same Redis, so a response cached by one is served by all. Redis expires entries itself (via
//! `PSETEX` from the entry's remaining freshness), while the entry's own timing stays the source of
//! truth for age.
//!
//! Every operation fails open: any Redis error or timeout is logged and treated as a cache miss, so
//! a Redis outage degrades to origin fetches rather than failing requests.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use super::storage::CacheStorage;
use super::{CacheEntry, CacheKey, StoredResponse, Variant};
use crate::*;

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
/// Bumped if the wire format changes; entries written by an older format decode as a miss.
const WIRE_VERSION: u8 = 1;

#[apply(schema!)]
pub struct RedisConfig {
	/// Connection URL, e.g. `redis://host:6379/0` or `rediss://host:6379` for TLS.
	pub url: String,
	/// Prefix prepended to every key, to namespace this cache within a shared Redis.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_prefix: Option<String>,
	/// Timeout applied to each Redis operation. On timeout the request falls through to the origin.
	#[serde(default, with = "serde_dur_option")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub operation_timeout: Option<Duration>,
}

/// Redis store. The connection manager is created on first use, so a Redis outage at startup does
/// not stop the gateway from booting.
pub struct RedisStorage {
	client: redis::Client,
	manager: OnceCell<ConnectionManager>,
	key_prefix: String,
	operation_timeout: Duration,
}

impl std::fmt::Debug for RedisStorage {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RedisStorage")
			.field("key_prefix", &self.key_prefix)
			.field("operation_timeout", &self.operation_timeout)
			.finish_non_exhaustive()
	}
}

impl RedisStorage {
	pub fn new(cfg: &RedisConfig) -> anyhow::Result<Self> {
		// Parses and validates the URL now; no network I/O yet.
		let client = redis::Client::open(cfg.url.as_str())
			.map_err(|e| anyhow::anyhow!("invalid redis url: {e}"))?;
		Ok(Self {
			client,
			manager: OnceCell::new(),
			key_prefix: cfg.key_prefix.clone().unwrap_or_default(),
			operation_timeout: cfg.operation_timeout.unwrap_or(DEFAULT_OPERATION_TIMEOUT),
		})
	}

	fn redis_key(&self, key: &CacheKey) -> String {
		format!("{}{}", self.key_prefix, key.to_storage_key())
	}

	/// Returns a cloned connection, initializing the manager on first use.
	///
	/// Establishing the connection is bounded two ways so it cannot hang: the manager config caps
	/// each connect/response attempt, and the whole init is wrapped in an outer timeout. Every caller
	/// shares this future via the `OnceCell`, so an unbounded init would block them all.
	async fn connection(&self) -> anyhow::Result<ConnectionManager> {
		let init = self.manager.get_or_try_init(|| {
			let config = redis::aio::ConnectionManagerConfig::new()
				.set_connection_timeout(self.operation_timeout)
				.set_response_timeout(self.operation_timeout)
				.set_number_of_retries(1);
			self.client.get_connection_manager_with_config(config)
		});
		match tokio::time::timeout(self.operation_timeout, init).await {
			Ok(Ok(m)) => Ok(m.clone()),
			Ok(Err(e)) => Err(anyhow::anyhow!("redis connection failed: {e}")),
			Err(_) => Err(anyhow::anyhow!("redis connection timed out")),
		}
	}

	/// Runs a Redis command, failing (rather than hanging) if it exceeds the operation timeout.
	async fn with_timeout<F, T>(&self, fut: F) -> anyhow::Result<T>
	where
		F: std::future::Future<Output = redis::RedisResult<T>>,
	{
		match tokio::time::timeout(self.operation_timeout, fut).await {
			Ok(Ok(v)) => Ok(v),
			Ok(Err(e)) => Err(anyhow::anyhow!("redis operation failed: {e}")),
			Err(_) => Err(anyhow::anyhow!("redis operation timed out")),
		}
	}
}

#[async_trait::async_trait]
impl CacheStorage for RedisStorage {
	async fn get(&self, key: &CacheKey) -> anyhow::Result<Option<CacheEntry>> {
		let mut conn = self.connection().await?;
		let redis_key = self.redis_key(key);
		let bytes: Option<Vec<u8>> = self
			.with_timeout(redis::cmd("GET").arg(&redis_key).query_async(&mut conn))
			.await?;
		let Some(bytes) = bytes else {
			return Ok(None);
		};
		match WireEntry::decode(&bytes) {
			Some(entry) => Ok(Some(entry)),
			None => {
				// A corrupt or stale-format entry is a miss, not a store failure: drop it so it stops
				// being fetched, and report the miss rather than an error.
				warn!("failed to decode cache entry; evicting");
				let _ = self
					.with_timeout(
						redis::cmd("DEL")
							.arg(&redis_key)
							.query_async::<()>(&mut conn),
					)
					.await;
				Ok(None)
			},
		}
	}

	async fn insert(&self, key: &CacheKey, value: CacheEntry) -> anyhow::Result<()> {
		// Expire the Redis key when the longest-lived variant's freshness runs out.
		let ttl = value.max_remaining_ttl(SystemTime::now());
		let ttl_ms = ttl.as_millis().max(1) as u64;
		let bytes =
			WireEntry::encode(&value).ok_or_else(|| anyhow::anyhow!("failed to encode cache entry"))?;
		let mut conn = self.connection().await?;
		let redis_key = self.redis_key(key);
		self
			.with_timeout(
				redis::cmd("SET")
					.arg(&redis_key)
					.arg(bytes)
					.arg("PX")
					.arg(ttl_ms)
					.query_async::<()>(&mut conn),
			)
			.await
	}
}

/// Serialized form of a cache entry (all variants of one resource). Times are stored absolute (Unix
/// millis) so an entry means the same thing regardless of which instance reads it.
///
/// Encoded with postcard: a compact binary format that stores the response bodies as raw bytes.
/// JSON would balloon each body into an array of numbers, and postcard is already in the build
/// (pulled by `phonenumber`), so it costs nothing extra here.
#[derive(Serialize, Deserialize)]
struct WireEntry {
	version: u8,
	vary: Vec<String>,
	variants: Vec<WireVariant>,
}

#[derive(Serialize, Deserialize)]
struct WireVariant {
	secondary: Vec<String>,
	#[serde(with = "http_serde::status_code")]
	status: StatusCode,
	#[serde(with = "http_serde::header_map")]
	headers: HeaderMap,
	body: Vec<u8>,
	response_time_unix_ms: u64,
	initial_age_ms: u64,
	lifetime_ms: u64,
}

impl WireEntry {
	fn encode(entry: &CacheEntry) -> Option<Vec<u8>> {
		let mut variants = Vec::with_capacity(entry.variants.len());
		for v in &entry.variants {
			let response_time_unix_ms = v
				.response
				.response_time
				.duration_since(UNIX_EPOCH)
				.ok()?
				.as_millis() as u64;
			variants.push(WireVariant {
				secondary: v.secondary.clone(),
				status: v.response.status,
				headers: v.response.headers.clone(),
				body: v.response.body.to_vec(),
				response_time_unix_ms,
				initial_age_ms: v.response.initial_age.as_millis() as u64,
				lifetime_ms: v.response.lifetime.as_millis() as u64,
			});
		}
		let wire = WireEntry {
			version: WIRE_VERSION,
			vary: entry.vary.clone(),
			variants,
		};
		postcard::to_stdvec(&wire).ok()
	}

	fn decode(bytes: &[u8]) -> Option<CacheEntry> {
		let wire: WireEntry = postcard::from_bytes(bytes).ok()?;
		if wire.version != WIRE_VERSION {
			return None;
		}
		let variants = wire
			.variants
			.into_iter()
			.map(|v| Variant {
				secondary: v.secondary,
				response: StoredResponse {
					status: v.status,
					headers: v.headers,
					body: Bytes::from(v.body),
					response_time: UNIX_EPOCH + Duration::from_millis(v.response_time_unix_ms),
					initial_age: Duration::from_millis(v.initial_age_ms),
					lifetime: Duration::from_millis(v.lifetime_ms),
				},
			})
			.collect();
		Some(CacheEntry {
			vary: wire.vary,
			variants,
		})
	}
}

#[cfg(test)]
mod tests {
	use ::http::{HeaderValue, header};

	use super::*;

	fn sample() -> CacheEntry {
		let mut headers = HeaderMap::new();
		headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
		CacheEntry {
			vary: vec!["accept-encoding".to_string()],
			variants: vec![Variant {
				secondary: vec!["gzip".to_string()],
				response: StoredResponse {
					status: StatusCode::OK,
					headers,
					body: Bytes::from_static(b"hello world"),
					response_time: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
					initial_age: Duration::from_secs(3),
					lifetime: Duration::from_secs(60),
				},
			}],
		}
	}

	#[test]
	fn wire_entry_round_trips() {
		let original = sample();
		let bytes = WireEntry::encode(&original).unwrap();
		let decoded = WireEntry::decode(&bytes).unwrap();
		assert_eq!(decoded.vary, original.vary);
		assert_eq!(decoded.variants.len(), 1);
		let (d, o) = (&decoded.variants[0], &original.variants[0]);
		assert_eq!(d.secondary, o.secondary);
		assert_eq!(d.response.status, o.response.status);
		assert_eq!(d.response.body, o.response.body);
		assert_eq!(d.response.initial_age, o.response.initial_age);
		assert_eq!(d.response.lifetime, o.response.lifetime);
		assert_eq!(d.response.response_time, o.response.response_time);
		assert_eq!(
			d.response.headers.get(header::CONTENT_TYPE).unwrap(),
			"text/plain"
		);
	}

	#[test]
	fn decode_rejects_garbage_and_wrong_version() {
		assert!(WireEntry::decode(b"not postcard").is_none());

		let mut wire: WireEntry = postcard::from_bytes(&WireEntry::encode(&sample()).unwrap()).unwrap();
		wire.version = 99;
		let bytes = postcard::to_stdvec(&wire).unwrap();
		assert!(WireEntry::decode(&bytes).is_none());
	}

	#[test]
	fn invalid_url_is_rejected_at_construction() {
		assert!(
			RedisStorage::new(&RedisConfig {
				url: "not a url".to_string(),
				key_prefix: None,
				operation_timeout: None,
			})
			.is_err()
		);
	}

	fn key() -> CacheKey {
		CacheKey {
			method: "GET".to_string(),
			scheme: "http".to_string(),
			authority: "example.com".to_string(),
			path: "/a".to_string(),
		}
	}

	/// A dead Redis must return an error in bounded time — never hang. The store reports the failure
	/// honestly; degrading it to a cache miss is the consumer's job (see the consumer test). Port 1
	/// is reserved and refuses connections. This guards the connection path being bounded rather than
	/// retrying with the library defaults.
	#[tokio::test]
	async fn dead_redis_errors_without_hanging() {
		let store = RedisStorage::new(&RedisConfig {
			url: "redis://127.0.0.1:1".to_string(),
			key_prefix: None,
			operation_timeout: Some(Duration::from_millis(200)),
		})
		.unwrap();

		// A generous ceiling: the operation must not hang, but connection refusal plus one retry can
		// legitimately take a few multiples of the configured timeout.
		let deadline = Duration::from_secs(3);

		tokio::time::timeout(deadline, async {
			assert!(
				store.get(&key()).await.is_err(),
				"get should error, not hang"
			);
			assert!(store.insert(&key(), sample()).await.is_err());
		})
		.await
		.expect("redis operations must not hang when the server is unreachable");
	}

	#[test]
	fn key_prefix_is_applied() {
		let store = RedisStorage::new(&RedisConfig {
			url: "redis://localhost:6379".to_string(),
			key_prefix: Some("agw:".to_string()),
			operation_timeout: None,
		})
		.unwrap();
		assert!(
			store
				.redis_key(&key())
				.starts_with("agw:GET http://example.com/a")
		);
	}
}
