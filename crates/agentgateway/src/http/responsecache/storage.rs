//! Backing stores for cached responses.
//!
//! Implementations decide where entries live and how they expire. Freshness itself is carried on
//! the entry's variants, so a store only needs to hand back what it was given; any expiry it does of
//! its own is an eviction optimization, not the source of truth.
//!
//! Errors are reported honestly rather than hidden: the caller decides that a failing cache degrades
//! to an origin fetch (fail-open), so that policy lives in one place instead of every backend.
//! Implementations must be non-blocking — an operation that cannot complete returns an error in
//! bounded time, not a hang.

use std::time::SystemTime;

use quick_cache::sync::Cache;

use super::{CacheEntry, CacheKey};

/// Where cached responses are kept. Kept object-safe so the backing store can be swapped without
/// touching the policy.
#[async_trait::async_trait]
pub trait CacheStorage: std::fmt::Debug + Send + Sync {
	/// Returns the entry for `key`, or `Ok(None)` if the store holds none. May return an entry with
	/// stale variants; the caller checks freshness. `Err` means the store itself is unavailable.
	async fn get(&self, key: &CacheKey) -> anyhow::Result<Option<CacheEntry>>;

	/// Stores `value` under `key`, replacing any existing entry.
	async fn insert(&self, key: &CacheKey, value: CacheEntry) -> anyhow::Result<()>;
}

/// Process-local store. Entries are not shared between gateway instances, so each replica warms its
/// own cache and a response may be served up to its full freshness lifetime by each.
#[derive(Debug)]
pub struct InMemoryStorage {
	entries: Cache<CacheKey, CacheEntry>,
}

impl InMemoryStorage {
	pub fn new(max_entries: usize) -> Self {
		Self {
			entries: Cache::new(max_entries.max(1)),
		}
	}
}

#[async_trait::async_trait]
impl CacheStorage for InMemoryStorage {
	async fn get(&self, key: &CacheKey) -> anyhow::Result<Option<CacheEntry>> {
		let Some(entry) = self.entries.get(key) else {
			return Ok(None);
		};
		// Drop entries whose variants have all aged out rather than handing back dead weight.
		if !entry.any_fresh(SystemTime::now()) {
			self.entries.remove(key);
			return Ok(None);
		}
		Ok(Some(entry))
	}

	async fn insert(&self, key: &CacheKey, value: CacheEntry) -> anyhow::Result<()> {
		self.entries.insert(key.clone(), value);
		Ok(())
	}
}
