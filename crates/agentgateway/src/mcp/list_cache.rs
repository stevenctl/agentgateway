use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rmcp::model::{CacheScope, ServerJsonRpcMessage, ServerNotification, ServerResult};

use crate::mcp::handler::ResolveKind;

/// Names seen while paging one target's list, only as far as resolution needed.
#[derive(Debug, Default)]
pub(crate) struct AccumulatedNames {
	names: HashSet<String>,
	ttl: Option<Duration>,
	uncachable: bool,
	complete: bool,
}

impl AccumulatedNames {
	pub fn add_page(&mut self, kind: ResolveKind, result: &ServerResult) {
		let (names, next_cursor, ttl_ms, cache_scope) = match (kind, result) {
			(ResolveKind::Tool, ServerResult::ListToolsResult(r)) => (
				r.tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>(),
				&r.next_cursor,
				r.ttl_ms,
				r.cache_scope,
			),
			(ResolveKind::Prompt, ServerResult::ListPromptsResult(r)) => (
				r.prompts.iter().map(|p| p.name.to_string()).collect(),
				&r.next_cursor,
				r.ttl_ms,
				r.cache_scope,
			),
			_ => return,
		};
		self.names.extend(names);
		self.complete = next_cursor.is_none();
		match cache_duration(ttl_ms, cache_scope) {
			Some(ttl) => self.ttl = Some(self.ttl.map_or(ttl, |t| t.min(ttl))),
			None => self.uncachable = true,
		}
	}
}

fn cache_duration(ttl_ms: Option<u64>, cache_scope: Option<CacheScope>) -> Option<Duration> {
	let ttl_ms = ttl_ms.unwrap_or(0);
	if ttl_ms == 0 {
		return None;
	}
	// Unknown future scopes are not safe to cache. Public and private are both
	// safe because this cache is partitioned by downstream MCP session.
	match cache_scope.unwrap_or_default() {
		CacheScope::Public | CacheScope::Private => Some(Duration::from_millis(ttl_ms)),
		_ => None,
	}
}

#[derive(Debug)]
struct CachedNames {
	names: HashSet<String>,
	/// Whether `names` covers the target's whole list. Incomplete entries can
	/// only prove a name is served, never that it isn't.
	complete: bool,
	expires_at: Instant,
}

#[derive(Debug)]
pub(crate) struct ListCacheLookup {
	/// Whether the target serves the name, when the cache can tell.
	pub served: Option<bool>,
	/// Pass back to `insert` so a refresh raced by an invalidation is dropped.
	pub generation: u64,
}

#[derive(Debug, Default)]
struct Slot {
	cached: Option<CachedNames>,
	/// Bumped on invalidation; outlives `cached` so in-flight probes that
	/// started before the invalidation can't repopulate stale names.
	generation: u64,
}

/// Per-upstream name sets seen during unprefixed name resolution probes.
///
/// This cache belongs to a Relay, which is scoped to one downstream MCP session.
/// That makes both public and private upstream entries safe to reuse without
/// serving a private result to another user/session.
#[derive(Debug, Default)]
pub(crate) struct ListCache {
	state: Mutex<HashMap<(String, ResolveKind), Slot>>,
}

impl ListCache {
	pub fn lookup(&self, target: &str, kind: ResolveKind, name: &str) -> ListCacheLookup {
		self.lookup_at(target, kind, name, Instant::now())
	}

	fn lookup_at(&self, target: &str, kind: ResolveKind, name: &str, now: Instant) -> ListCacheLookup {
		let mut state = self.state.lock().expect("list cache lock");
		let Some(slot) = state.get_mut(&(target.to_string(), kind)) else {
			return ListCacheLookup {
				served: None,
				generation: 0,
			};
		};
		let served = match &slot.cached {
			Some(cached) if now < cached.expires_at => {
				if cached.names.contains(name) {
					Some(true)
				} else if cached.complete {
					Some(false)
				} else {
					None
				}
			},
			Some(_) => {
				slot.cached = None;
				None
			},
			None => None,
		};
		ListCacheLookup {
			served,
			generation: slot.generation,
		}
	}

	pub fn insert(&self, target: &str, kind: ResolveKind, generation: u64, names: AccumulatedNames) {
		self.insert_at(target, kind, generation, names, Instant::now());
	}

	fn insert_at(
		&self,
		target: &str,
		kind: ResolveKind,
		generation: u64,
		names: AccumulatedNames,
		now: Instant,
	) {
		let cached = (!names.uncachable)
			.then_some(names.ttl)
			.flatten()
			.and_then(|ttl| now.checked_add(ttl))
			.map(|expires_at| CachedNames {
				names: names.names,
				complete: names.complete,
				expires_at,
			});
		let mut state = self.state.lock().expect("list cache lock");
		let slot = state.entry((target.to_string(), kind)).or_default();
		if slot.generation != generation {
			return;
		}
		match cached {
			Some(cached) => {
				// A concurrent probe of the same generation may have cached the full
				// list; a partial page set adds nothing over it.
				let downgrades = !cached.complete
					&& slot
						.cached
						.as_ref()
						.is_some_and(|c| c.complete && now < c.expires_at);
				if !downgrades {
					slot.cached = Some(cached);
				}
			},
			None => slot.cached = None,
		}
	}

	fn invalidate(&self, target: &str, kind: ResolveKind) {
		let mut state = self.state.lock().expect("list cache lock");
		let slot = state.entry((target.to_string(), kind)).or_default();
		slot.cached = None;
		slot.generation = slot.generation.wrapping_add(1);
	}

	pub fn invalidate_from_message(&self, target: &str, message: &ServerJsonRpcMessage) {
		let ServerJsonRpcMessage::Notification(notification) = message else {
			return;
		};
		match &notification.notification {
			ServerNotification::ToolListChangedNotification(_) => {
				self.invalidate(target, ResolveKind::Tool)
			},
			ServerNotification::PromptListChangedNotification(_) => {
				self.invalidate(target, ResolveKind::Prompt)
			},
			_ => {},
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use rmcp::model::{
		ListPromptsResult, ListToolsResult, PromptListChangedNotification, Tool,
		ToolListChangedNotification,
	};

	use super::*;

	fn tools_page(
		names: &[&str],
		ttl_ms: Option<u64>,
		cache_scope: Option<CacheScope>,
		next_cursor: Option<&str>,
	) -> ServerResult {
		ServerResult::ListToolsResult(ListToolsResult {
			tools: names
				.iter()
				.map(|n| Tool::new(n.to_string(), "", Arc::new(serde_json::Map::new())))
				.collect(),
			ttl_ms,
			cache_scope,
			next_cursor: next_cursor.map(Into::into),
			..Default::default()
		})
	}

	fn accumulated(kind: ResolveKind, pages: &[&ServerResult]) -> AccumulatedNames {
		let mut acc = AccumulatedNames::default();
		for page in pages {
			acc.add_page(kind, page);
		}
		acc
	}

	fn served_at(
		cache: &ListCache,
		target: &str,
		kind: ResolveKind,
		name: &str,
		now: Instant,
	) -> Option<bool> {
		cache.lookup_at(target, kind, name, now).served
	}

	#[test]
	fn respects_upstream_ttl_and_scope() {
		let now = Instant::now();
		for scope in [None, Some(CacheScope::Public), Some(CacheScope::Private)] {
			// An absent cacheScope defaults to public per SEP-2549.
			let cache = ListCache::default();
			let page = tools_page(&["echo"], Some(100), scope, None);
			cache.insert_at("target", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&page]), now);
			assert_eq!(
				served_at(&cache, "target", ResolveKind::Tool, "echo", now),
				Some(true)
			);
		}
	}

	#[test]
	fn treats_missing_and_zero_ttl_as_immediately_stale() {
		let now = Instant::now();
		for ttl_ms in [None, Some(0)] {
			let cache = ListCache::default();
			let fresh = tools_page(&["echo"], Some(100), Some(CacheScope::Public), None);
			cache.insert_at(
				"target",
				ResolveKind::Tool,
				0,
				accumulated(ResolveKind::Tool, &[&fresh]),
				now,
			);

			let stale = tools_page(&["echo"], ttl_ms, Some(CacheScope::Public), None);
			cache.insert_at(
				"target",
				ResolveKind::Tool,
				0,
				accumulated(ResolveKind::Tool, &[&stale]),
				now,
			);
			assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "echo", now), None);
		}
	}

	#[test]
	fn expires_at_the_min_ttl_across_pages() {
		let now = Instant::now();
		let cache = ListCache::default();
		let first = tools_page(&["a"], Some(100), Some(CacheScope::Public), Some("page2"));
		let second = tools_page(&["b"], Some(50), Some(CacheScope::Public), None);
		cache.insert_at(
			"target",
			ResolveKind::Tool,
			0,
			accumulated(ResolveKind::Tool, &[&first, &second]),
			now,
		);

		let live = now + Duration::from_millis(49);
		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "a", live), Some(true));
		let expired = now + Duration::from_millis(50);
		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "a", expired), None);
	}

	#[test]
	fn any_uncachable_page_prevents_caching() {
		let now = Instant::now();
		let cache = ListCache::default();
		let first = tools_page(&["a"], None, None, Some("page2"));
		let second = tools_page(&["b"], Some(100), Some(CacheScope::Public), None);
		cache.insert_at(
			"target",
			ResolveKind::Tool,
			0,
			accumulated(ResolveKind::Tool, &[&first, &second]),
			now,
		);
		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "b", now), None);
	}

	#[test]
	fn incomplete_entries_only_answer_positively() {
		let now = Instant::now();
		let cache = ListCache::default();
		// Probe stopped at page 1 of 2: later names are unknown, not absent.
		let page = tools_page(&["seen"], Some(100), Some(CacheScope::Public), Some("page2"));
		cache.insert_at("target", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&page]), now);

		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "seen", now), Some(true));
		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "unseen", now), None);
	}

	#[test]
	fn complete_entries_answer_negatively() {
		let now = Instant::now();
		let cache = ListCache::default();
		let page = tools_page(&["seen"], Some(100), Some(CacheScope::Public), None);
		cache.insert_at("target", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&page]), now);

		assert_eq!(
			served_at(&cache, "target", ResolveKind::Tool, "unseen", now),
			Some(false)
		);
	}

	#[test]
	fn incomplete_probe_does_not_downgrade_a_complete_entry() {
		let now = Instant::now();
		let cache = ListCache::default();
		let full = tools_page(&["a", "b"], Some(100), Some(CacheScope::Public), None);
		cache.insert_at("target", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&full]), now);

		// A concurrent probe that stopped after page 1 must not erase the
		// complete entry's ability to answer negatively.
		let partial = tools_page(&["a"], Some(100), Some(CacheScope::Public), Some("page2"));
		cache.insert_at(
			"target",
			ResolveKind::Tool,
			0,
			accumulated(ResolveKind::Tool, &[&partial]),
			now,
		);

		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "b", now), Some(true));
		assert_eq!(
			served_at(&cache, "target", ResolveKind::Tool, "unseen", now),
			Some(false)
		);
	}

	#[test]
	fn list_changed_invalidates_only_the_matching_target_and_kind() {
		let now = Instant::now();
		let cache = ListCache::default();
		let tools = tools_page(&["echo"], Some(100), Some(CacheScope::Public), None);
		let prompts = ServerResult::ListPromptsResult(ListPromptsResult {
			ttl_ms: Some(100),
			cache_scope: Some(CacheScope::Private),
			..Default::default()
		});
		cache.insert_at("target", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&tools]), now);
		cache.insert_at(
			"target",
			ResolveKind::Prompt,
			0,
			accumulated(ResolveKind::Prompt, &[&prompts]),
			now,
		);
		cache.insert_at("other", ResolveKind::Tool, 0, accumulated(ResolveKind::Tool, &[&tools]), now);

		let notification = ServerJsonRpcMessage::notification(ServerNotification::from(
			ToolListChangedNotification::default(),
		));
		cache.invalidate_from_message("target", &notification);

		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "echo", now), None);
		assert_eq!(
			served_at(&cache, "target", ResolveKind::Prompt, "unseen", now),
			Some(false)
		);
		assert_eq!(
			served_at(&cache, "other", ResolveKind::Tool, "echo", now),
			Some(true)
		);

		let notification = ServerJsonRpcMessage::notification(ServerNotification::from(
			PromptListChangedNotification::default(),
		));
		cache.invalidate_from_message("target", &notification);
		assert_eq!(
			served_at(&cache, "target", ResolveKind::Prompt, "unseen", now),
			None
		);
	}

	#[test]
	fn list_changed_during_refresh_prevents_stale_repopulation() {
		let now = Instant::now();
		let cache = ListCache::default();
		let lookup = cache.lookup_at("target", ResolveKind::Tool, "echo", now);
		assert_eq!(lookup.served, None);

		cache.invalidate("target", ResolveKind::Tool);
		let page = tools_page(&["echo"], Some(100), Some(CacheScope::Public), None);
		cache.insert_at(
			"target",
			ResolveKind::Tool,
			lookup.generation,
			accumulated(ResolveKind::Tool, &[&page]),
			now,
		);

		assert_eq!(served_at(&cache, "target", ResolveKind::Tool, "echo", now), None);
	}

	#[test]
	fn private_entries_are_partitioned_by_downstream_session() {
		let now = Instant::now();
		let first_session = ListCache::default();
		let second_session = ListCache::default();
		let page = tools_page(&["echo"], Some(100), Some(CacheScope::Private), None);
		first_session.insert_at(
			"target",
			ResolveKind::Tool,
			0,
			accumulated(ResolveKind::Tool, &[&page]),
			now,
		);

		assert_eq!(
			served_at(&first_session, "target", ResolveKind::Tool, "echo", now),
			Some(true)
		);
		assert_eq!(
			served_at(&second_session, "target", ResolveKind::Tool, "echo", now),
			None
		);
	}
}
