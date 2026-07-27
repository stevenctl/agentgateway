//! Redis-backed shared cache store.
//!
//! Unlike the in-memory store, entries here are shared across every gateway instance pointed at the
//! same Redis, so a response cached by one is served by all. Redis expires entries itself (via
//! `SET PX` from the entry's remaining freshness), while the entry's own timing stays the source of
//! truth for age.
//!
//! The server is named as a backend rather than a URL, so the socket is opened through the
//! gateway's own connector: backend TLS, tunnels, service discovery and endpoint selection apply
//! exactly as they do for any other upstream. redis-rs then multiplexes every command for this
//! store over that one socket.
//!
//! Errors are returned rather than hidden; the consumer degrades them to a cache miss. Each
//! operation is bounded by `operation_timeout` so a wedged server cannot stall a request.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use redis::aio::MultiplexedConnection;
use redis::{AsyncConnectionConfig, RedisConnectionInfo};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::storage::CacheStorage;
use super::{CacheEntry, CacheKey, StoredResponse, Variant};
use crate::client::HboneSourceRole;
use crate::proxy::httpproxy::{PolicyClient, build_transport};
use crate::proxy::resolve_simple_backend_with_policies;
use crate::proxy::tcpproxy::{TCPProxy, get_backend_policies};
use crate::types::agent::{SimpleBackendReference, SimpleBackendReferenceWithPolicies};
use crate::*;

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
/// Bumped if the wire format changes; entries written by an older format decode as a miss.
const WIRE_VERSION: u8 = 1;

#[apply(schema!)]
pub struct RedisConfig {
	/// Redis server to connect to, and the backend policies used when connecting to it.
	#[serde(flatten)]
	pub target: SimpleBackendReferenceWithPolicies,
	/// Database index selected after connecting. Defaults to 0.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub db: Option<i64>,
	/// Username sent with `AUTH`, for servers using ACLs.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub username: Option<String>,
	/// Password sent with `AUTH`.
	#[serde(
		default,
		serialize_with = "ser_redact",
		deserialize_with = "deser_key_from_file_option",
		skip_serializing_if = "Option::is_none"
	)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<FileOrInline>"))]
	pub password: Option<SecretString>,
	/// Prefix prepended to every key, to namespace this cache within a shared Redis.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_prefix: Option<String>,
	/// Timeout applied to each Redis operation. On timeout the request falls through to the origin.
	#[serde(default, with = "serde_dur_option")]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	pub operation_timeout: Option<Duration>,
}

/// A lazily established, self-healing connection to one Redis server.
///
/// redis-rs pipelines every command over the single socket this holds, so one is enough for any
/// number of concurrent requests. Kept separate from [`RedisStorage`] so that policies pointing at
/// the same backend can later share one of these instead of one each.
pub struct RedisConnection {
	target: SimpleBackendReferenceWithPolicies,
	info: RedisConnectionInfo,
	state: Mutex<ConnectionState>,
}

#[derive(Default)]
struct ConnectionState {
	/// Bumped on every reconnect, so a failure reported against a connection that has already been
	/// replaced cannot evict its replacement.
	generation: u64,
	current: Option<MultiplexedConnection>,
}

impl std::fmt::Debug for RedisConnection {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// `info` carries the password; print only what is safe to log.
		f.debug_struct("RedisConnection")
			.field("target", &self.target.target)
			.field("db", &self.info.db)
			.finish_non_exhaustive()
	}
}

impl RedisConnection {
	fn new(cfg: &RedisConfig) -> Self {
		Self {
			target: cfg.target.clone(),
			info: RedisConnectionInfo {
				db: cfg.db.unwrap_or_default(),
				username: cfg.username.clone(),
				password: cfg.password.as_ref().map(|p| p.expose_secret().to_string()),
				..Default::default()
			},
			state: Mutex::new(ConnectionState::default()),
		}
	}

	/// Returns the live connection, establishing it on first use. The generation identifies which
	/// connection was handed out, so a caller that later sees an error invalidates only that one.
	async fn get(
		&self,
		client: &PolicyClient,
		timeout: Duration,
	) -> anyhow::Result<(u64, MultiplexedConnection)> {
		// Connecting under the lock is deliberate: callers arriving during a connect wait for it
		// rather than each opening a socket of their own.
		let mut state = self.state.lock().await;
		if let Some(conn) = &state.current {
			return Ok((state.generation, conn.clone()));
		}
		let conn = tokio::time::timeout(timeout, self.connect(client))
			.await
			.map_err(|_| anyhow::anyhow!("redis connection timed out"))??;
		state.current = Some(conn.clone());
		Ok((state.generation, conn))
	}

	/// Drops `generation` so the next caller reconnects. Requests already in flight on it keep their
	/// own clone and finish on the old socket.
	async fn invalidate(&self, generation: u64) {
		let mut state = self.state.lock().await;
		if state.generation == generation {
			state.current = None;
			state.generation += 1;
		}
	}

	/// Opens a socket through the gateway's connector, applying the backend's policies, and hands it
	/// to redis-rs. redis-rs still performs its own `AUTH`/`SELECT` handshake over it.
	async fn connect(&self, client: &PolicyClient) -> anyhow::Result<MultiplexedConnection> {
		let inputs = client.inputs.as_ref();
		let backend = resolve_simple_backend_with_policies(&self.target.target, inputs)?;
		let policies = get_backend_policies(inputs, &backend, self.target.policies.as_slice(), None);
		let call = TCPProxy::build_backend_call(
			&mut None,
			None,
			inputs,
			&backend.backend,
			policies,
			Some(HboneSourceRole::Gateway),
		)?;
		let transport = build_transport(
			inputs,
			&call,
			Some(HboneSourceRole::Gateway),
			call.backend_policies.backend_tls.clone(),
			call.backend_policies.tunnel.as_ref(),
			None,
		)
		.await?;
		let socket = inputs.upstream.connect_raw(call.target, transport).await?;
		let (conn, driver) =
			MultiplexedConnection::new_with_config(&self.info, socket, AsyncConnectionConfig::new())
				.await?;
		// Pumps the socket for as long as any clone of the connection is alive.
		tokio::spawn(driver);
		Ok(conn)
	}
}

/// Redis store. Nothing connects until the first cache operation, so an unreachable Redis at
/// startup does not stop the gateway from booting.
#[derive(Debug)]
pub struct RedisStorage {
	conn: Arc<RedisConnection>,
	key_prefix: String,
	operation_timeout: Duration,
}

impl RedisStorage {
	pub fn new(cfg: &RedisConfig) -> anyhow::Result<Self> {
		if matches!(cfg.target.target.as_ref(), SimpleBackendReference::Invalid) {
			anyhow::bail!(
				"redis store requires a backend: set one of 'host', 'name'/'port', or 'backend'"
			);
		}
		Ok(Self {
			conn: Arc::new(RedisConnection::new(cfg)),
			key_prefix: cfg.key_prefix.clone().unwrap_or_default(),
			operation_timeout: cfg.operation_timeout.unwrap_or(DEFAULT_OPERATION_TIMEOUT),
		})
	}

	fn redis_key(&self, key: &CacheKey) -> String {
		format!("{}{}", self.key_prefix, key.to_storage_key())
	}

	/// Runs one command, bounded by the operation timeout. Any failure invalidates the connection, so
	/// the next call reconnects rather than reusing a socket whose state we no longer know.
	async fn command<T: redis::FromRedisValue>(
		&self,
		client: &PolicyClient,
		cmd: &redis::Cmd,
	) -> anyhow::Result<T> {
		let (generation, mut conn) = self.conn.get(client, self.operation_timeout).await?;
		let res = tokio::time::timeout(self.operation_timeout, cmd.query_async(&mut conn)).await;
		match res {
			Ok(Ok(v)) => Ok(v),
			Ok(Err(e)) => {
				self.conn.invalidate(generation).await;
				Err(anyhow::anyhow!("redis operation failed: {e}"))
			},
			Err(_) => {
				self.conn.invalidate(generation).await;
				Err(anyhow::anyhow!("redis operation timed out"))
			},
		}
	}
}

#[async_trait::async_trait]
impl CacheStorage for RedisStorage {
	async fn get(&self, client: &PolicyClient, key: &CacheKey) -> anyhow::Result<Option<CacheEntry>> {
		let redis_key = self.redis_key(key);
		let bytes: Option<Vec<u8>> = self
			.command(client, redis::cmd("GET").arg(&redis_key))
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
					.command::<()>(client, redis::cmd("DEL").arg(&redis_key))
					.await;
				Ok(None)
			},
		}
	}

	async fn insert(
		&self,
		client: &PolicyClient,
		key: &CacheKey,
		value: CacheEntry,
	) -> anyhow::Result<()> {
		// Expire the Redis key when the longest-lived variant's freshness runs out.
		let ttl = value.max_remaining_ttl(SystemTime::now());
		let ttl_ms = ttl.as_millis().max(1) as u64;
		let bytes =
			WireEntry::encode(&value).ok_or_else(|| anyhow::anyhow!("failed to encode cache entry"))?;
		let redis_key = self.redis_key(key);
		self
			.command(
				client,
				redis::cmd("SET")
					.arg(&redis_key)
					.arg(bytes)
					.arg("PX")
					.arg(ttl_ms),
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
	use crate::test_helpers::policy_client;

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

	fn config(host: &str) -> RedisConfig {
		serde_json::from_value(serde_json::json!({"host": host})).unwrap()
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

	/// The store names a backend, so a config that names none must fail at construction rather than
	/// on the first request.
	#[test]
	fn backend_is_required() {
		let cfg: RedisConfig = serde_json::from_value(serde_json::json!({})).unwrap();
		assert!(RedisStorage::new(&cfg).is_err());
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
	/// is reserved and refuses connections. This guards the connect path being bounded rather than
	/// retrying with the library defaults.
	#[tokio::test]
	async fn dead_redis_errors_without_hanging() {
		let mut cfg = config("127.0.0.1:1");
		cfg.operation_timeout = Some(Duration::from_millis(200));
		let store = RedisStorage::new(&cfg).unwrap();
		let client = policy_client();

		// A generous ceiling: the operation must not hang, but connection refusal plus one retry can
		// legitimately take a few multiples of the configured timeout.
		let deadline = Duration::from_secs(3);

		tokio::time::timeout(deadline, async {
			assert!(
				store.get(&client, &key()).await.is_err(),
				"get should error, not hang"
			);
			assert!(store.insert(&client, &key(), sample()).await.is_err());
		})
		.await
		.expect("redis operations must not hang when the server is unreachable");
	}

	#[test]
	fn key_prefix_is_applied() {
		let mut cfg = config("localhost:6379");
		cfg.key_prefix = Some("agw:".to_string());
		let store = RedisStorage::new(&cfg).unwrap();
		assert!(
			store
				.redis_key(&key())
				.starts_with("agw:GET http://example.com/a")
		);
	}
}
