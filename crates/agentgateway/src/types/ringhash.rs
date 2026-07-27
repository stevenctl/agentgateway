//! Ketama-style consistent hash ring: construction from weighted endpoint keys, and the
//! lookup/walk over it. Endpoint selection — bucket ordering, health, and capacity filtering —
//! lives in [`crate::types::loadbalancer`].

use std::collections::HashSet;
use std::sync::Arc;

use crate::types::loadbalancer::EndpointKey;

/// Ring points per unit of endpoint capacity (nginx's ketama allocation: weight * 160).
/// Points depend only on the endpoint's own weight — unlike Envoy's globally-rescaled ring,
/// membership changes never reallocate the surviving endpoints' points, so a change remaps
/// only the keys owned by the endpoints that actually changed.
const POINTS_PER_WEIGHT: u64 = 160;
/// Floor on total ring size (matching Envoy's default minimum). Below it, per-endpoint points
/// scale up proportionally so small clusters still spread keys evenly.
const MIN_RING_SIZE: u64 = 1024;
/// Cap on total ring size. Beyond it, per-endpoint points scale down proportionally
/// (weights quantize, and stability across the boundary degrades slightly).
const MAX_RING_SIZE: u64 = 65536;

/// Consistent-hash ring over a group's configured endpoints. Only built for services that a
/// loadBalancing.consistentHash policy actually routes to.
#[derive(Debug)]
pub struct HashRing {
	/// (ring point, owning endpoint key), sorted by point. Keys resolve against any group
	/// snapshot, so the ring is independent of eviction state and IndexMap ordering.
	entries: Vec<(u64, EndpointKey)>,
	/// Distinct endpoints in `entries`; lets `walk` stop once every endpoint has been offered
	/// instead of scanning all remaining points.
	unique_endpoints: usize,
}

/// Builds a ketama-style ring from `(endpoint key, weight)` pairs: each entry hashes
/// `{endpoint_key}_{i}` with xxhash64, sorted by point for binary-search lookup. What goes into
/// the ring — and why unviable endpoints stay in it — is decided by the caller
/// (`EndpointGroup::build_ring`).
pub fn build<'a>(weighted: impl Iterator<Item = (&'a EndpointKey, u64)>) -> Arc<HashRing> {
	let weighted: Vec<(&EndpointKey, u64)> = weighted.filter(|(_, w)| *w > 0).collect();
	let total_points: u64 = weighted.iter().map(|(_, w)| w * POINTS_PER_WEIGHT).sum();
	if total_points == 0 {
		return Arc::new(HashRing {
			entries: vec![],
			unique_endpoints: 0,
		});
	}
	// Scale the whole ring into [MIN, MAX]; scaling every endpoint by the same factor preserves
	// weight proportions.
	let scale = if total_points > MAX_RING_SIZE {
		MAX_RING_SIZE as f64 / total_points as f64
	} else if total_points < MIN_RING_SIZE {
		MIN_RING_SIZE as f64 / total_points as f64
	} else {
		1.0
	};

	let unique_endpoints = weighted.len();
	let mut entries = Vec::with_capacity(total_points.clamp(MIN_RING_SIZE, MAX_RING_SIZE) as usize);
	for (key, weight) in weighted {
		let points = (((weight * POINTS_PER_WEIGHT) as f64 * scale).round() as u64).max(1);
		for i in 0..points {
			let point = crate::http::loadbalancing::hash(format!("{key}_{i}").as_bytes());
			entries.push((point, key.clone()));
		}
	}
	entries.sort_unstable();
	Arc::new(HashRing {
		entries,
		unique_endpoints,
	})
}

impl HashRing {
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	/// Iterates owning endpoint keys starting at the ring position owning `hash` (the first
	/// point at or after it, wrapping), skipping repeats — the ketama "walk to the next
	/// host" order used when the owning endpoint is not viable.
	pub fn walk(&self, hash: u64) -> impl Iterator<Item = &EndpointKey> + '_ {
		let start = self.entries.partition_point(|(p, _)| *p < hash);
		let len = self.entries.len();
		let mut seen: HashSet<&EndpointKey> = HashSet::new();
		// The first key skips `seen`: avoid allocating a set we'll usually never read.
		let mut first: Option<&EndpointKey> = None;
		let mut off = 0;
		std::iter::from_fn(move || {
			if let Some(f) = first
				&& seen.is_empty()
			{
				seen.insert(f);
			}
			while seen.len() < self.unique_endpoints && off < len {
				let (_, key) = &self.entries[(start + off) % len];
				off += 1;
				if first.is_none() {
					first = Some(key);
					return Some(key);
				}
				if seen.insert(key) {
					return Some(key);
				}
			}
			None
		})
	}

	#[cfg(test)]
	pub(crate) fn entries(&self) -> &[(u64, EndpointKey)] {
		&self.entries
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	const POD_NAMES: [&str; 10] = [
		"pod-0", "pod-1", "pod-2", "pod-3", "pod-4", "pod-5", "pod-6", "pod-7", "pod-8", "pod-9",
	];

	/// Ring over the given `(endpoint key, weight)` pairs.
	fn ring(keys: &[(&str, u64)]) -> Arc<HashRing> {
		let owned: Vec<(EndpointKey, u64)> = keys
			.iter()
			.map(|(k, w)| (EndpointKey::from(*k), *w))
			.collect();
		build(owned.iter().map(|(k, w)| (k, *w)))
	}

	fn owner(ring: &HashRing, hash: u64) -> EndpointKey {
		ring.walk(hash).next().expect("non-empty ring").clone()
	}

	fn key(s: &str) -> u64 {
		crate::http::loadbalancing::hash(s.as_bytes())
	}

	// Two gateways given the same endpoints must agree on where every session goes, so the ring
	// cannot depend on insertion order or on any per-process state.
	#[test]
	fn ring_is_deterministic_regardless_of_input_order() {
		let a = ring(&[("e0", 1), ("e1", 1), ("e2", 1)]);
		let b = ring(&[("e2", 1), ("e0", 1), ("e1", 1)]);
		assert_eq!(a.entries(), b.entries());
	}

	// A fully drained service has nowhere to send traffic; the ring must say so rather than
	// hand back a stale owner.
	#[test]
	fn ring_is_empty_when_every_endpoint_is_drained() {
		assert!(ring(&[("e0", 0), ("e1", 0)]).is_empty());
		assert!(!ring(&[("e0", 0), ("e1", 1)]).is_empty());
	}

	// An endpoint given twice the capacity should serve roughly twice the sessions.
	#[test]
	fn ring_gives_bigger_endpoints_proportionally_more_of_the_keyspace() {
		let r = ring(&[("big", 3), ("small", 1)]);
		let big = r.entries().iter().filter(|(_, k)| k == "big").count();
		let small = r.entries().iter().filter(|(_, k)| k == "small").count();
		assert_eq!(big, small * 3, "big={big} small={small}");
	}

	// A two-pod service would get only 320 points at the raw allocation, enough for one pod to
	// own a visibly lopsided share of sessions.
	#[test]
	fn ring_stays_large_enough_to_balance_small_services() {
		let r = ring(&[("e0", 1), ("e1", 1)]);
		assert!(
			r.entries().len() as u64 >= MIN_RING_SIZE,
			"{} points",
			r.entries().len()
		);
	}

	#[test]
	fn ring_spreads_sessions_evenly_across_equal_endpoints() {
		let r = ring(&[("e0", 1), ("e1", 1), ("e2", 1), ("e3", 1)]);
		let mut counts = std::collections::HashMap::new();
		let total = 20_000;
		for i in 0..total {
			*counts
				.entry(owner(&r, key(&format!("user-{i}"))))
				.or_insert(0) += 1;
		}
		assert_eq!(counts.len(), 4);
		let ideal = total / 4;
		for (k, c) in &counts {
			let skew = (*c as f64 - ideal as f64).abs() / ideal as f64;
			assert!(
				skew < 0.10,
				"{k} took {c} of {total} sessions (ideal {ideal})"
			);
		}
	}

	// The point of consistent hashing: scaling a deployment down must not disturb sessions pinned
	// to the pods that survive. A naive `hash % n` would move nearly all of them.
	//
	// Uses 10 pods so both rings sit above `MIN_RING_SIZE` unscaled. Below that floor the two
	// rings scale by different factors, survivors gain points, and some sessions do move between
	// them — balance is preferred over stability for small services.
	#[test]
	fn scaling_down_only_moves_the_sessions_the_removed_pod_owned() {
		let pods: Vec<(&str, u64)> = POD_NAMES.iter().map(|n| (*n, 1)).collect();
		let before = ring(&pods);
		let after = ring(&pods[..pods.len() - 1]);
		let removed = POD_NAMES[POD_NAMES.len() - 1];

		let (mut owned_by_removed, mut moved) = (0, 0);
		for i in 0..10_000 {
			let h = key(&format!("user-{i}"));
			let was = owner(&before, h);
			if was == removed {
				owned_by_removed += 1;
			} else if owner(&after, h) != was {
				moved += 1;
			}
		}
		assert!(owned_by_removed > 0, "test must exercise the removed pod");
		assert_eq!(moved, 0, "{moved} sessions moved off surviving pods");
	}

	// When the owning pod is down, the walk has to offer every other pod in turn — and offer each
	// one once, so the caller does not re-test the same pod hundreds of times.
	#[test]
	fn walk_offers_every_other_endpoint_exactly_once() {
		let r = ring(&[("e0", 1), ("e1", 1), ("e2", 1)]);
		let order: Vec<EndpointKey> = r.walk(key("user-0")).cloned().collect();
		assert_eq!(order.len(), 3, "{order:?}");
		assert_eq!(order.iter().collect::<HashSet<_>>().len(), 3, "{order:?}");
	}
}
