use std::sync::Arc;

use crate::cel::Expression;
use crate::store::HasExpressions;
use crate::*;

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "LoadBalancingPolicy"))]
pub struct Policy {
	#[serde(flatten)]
	pub algorithm: Algorithm,
}

/// The load balancing algorithm used to select an endpoint. Exactly one may be set.
#[apply(schema!)]
pub enum Algorithm {
	/// Consistently hash requests to backend endpoints, providing best-effort session affinity:
	/// requests with the same key are routed to the same endpoint as long as the endpoint set is
	/// stable.
	ConsistentHash(ConsistentHash),
}

#[apply(schema!)]
#[cfg_attr(feature = "schema", schemars(rename = "ConsistentHash"))]
pub struct ConsistentHash {
	/// CEL expression evaluated against the request; its result is the hash key, so requests
	/// yielding the same value pin to the same endpoint. Requests where evaluation fails or
	/// returns null are not hashed (they fall back to the default algorithm). For example:
	/// `request.headers["x-session-id"]`, `request.headers.cookie("sid")`, or `source.address`.
	pub key: Arc<Expression>,
}

impl HasExpressions for Policy {
	fn expressions(&self) -> impl Iterator<Item = &Expression> {
		let Algorithm::ConsistentHash(ch) = &self.algorithm;
		std::iter::once(ch.key.as_ref())
	}
}

impl Policy {
	/// Computes the consistent-hash key for a request, or None when the key expression fails or
	/// yields null (callers fall back to the default load balancing algorithm).
	pub fn request_hash(&self, req: &http::Request) -> Option<u64> {
		let Algorithm::ConsistentHash(ch) = &self.algorithm;
		let exec = cel::Executor::new_request(req);
		match exec.eval(ch.key.as_ref()).ok()?.json().ok()? {
			serde_json::Value::Null => None,
			serde_json::Value::String(s) => Some(hash(s.as_bytes())),
			other => Some(hash(other.to_string().as_bytes())),
		}
	}
}

/// Request-key and ring-point hash. xxhash64 with zero seed, matching Envoy's default
/// `XX_HASH` ring hash function; must stay stable so mappings agree across instances and restarts.
pub fn hash(bytes: &[u8]) -> u64 {
	twox_hash::XxHash64::oneshot(0, bytes)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::tests_common::request;

	fn parse(v: serde_json::Value) -> Policy {
		serde_json::from_value(v).expect("policy must parse")
	}

	#[test]
	fn parses_consistent_hash_algorithm() {
		let pol = parse(serde_json::json!({"consistentHash": {"key": "request.method"}}));
		let Algorithm::ConsistentHash(_) = &pol.algorithm;
	}

	#[test]
	fn rejects_unknown_or_missing_algorithm() {
		// An unknown algorithm arm is rejected.
		serde_json::from_value::<Policy>(serde_json::json!({"roundRobin": {}}))
			.expect_err("unknown algorithm must be rejected");
		// consistentHash requires a key expression.
		serde_json::from_value::<Policy>(serde_json::json!({"consistentHash": {}}))
			.expect_err("a key is required");
		// No algorithm at all is rejected.
		serde_json::from_value::<Policy>(serde_json::json!({})).expect_err("an algorithm is required");
	}

	#[test]
	fn hashes_header_expression() {
		let pol = parse(serde_json::json!({"consistentHash": {"key": "request.headers[\"x-user\"]"}}));
		let req = request(
			"http://example.com/",
			::http::Method::GET,
			&[("x-user", "alice")],
		);
		assert_eq!(pol.request_hash(&req), Some(hash(b"alice")));
	}

	#[test]
	fn hashes_cookie_expression() {
		let pol =
			parse(serde_json::json!({"consistentHash": {"key": "request.headers.cookie(\"sid\")"}}));
		let req = request(
			"http://example.com/",
			::http::Method::GET,
			&[("cookie", "other=1; sid=abc")],
		);
		assert_eq!(pol.request_hash(&req), Some(hash(b"abc")));
	}

	#[test]
	fn hashes_query_expression() {
		let pol =
			parse(serde_json::json!({"consistentHash": {"key": "request.uri.query(\"user\")[0]"}}));
		let req = request(
			"http://example.com/path?a=1&user=bob",
			::http::Method::GET,
			&[],
		);
		assert_eq!(pol.request_hash(&req), Some(hash(b"bob")));
	}

	#[test]
	fn non_string_result_is_hashed() {
		let pol = parse(serde_json::json!({"consistentHash": {"key": "request.method"}}));
		let req = request("http://example.com/", ::http::Method::GET, &[]);
		assert_eq!(pol.request_hash(&req), Some(hash(b"GET")));
	}

	#[test]
	fn absent_key_yields_no_hash() {
		// Evaluation that resolves to null (missing header) produces no hash rather than an error,
		// so the caller falls back to the default algorithm.
		let pol = parse(serde_json::json!({"consistentHash": {"key": "request.headers[\"absent\"]"}}));
		let req = request("http://example.com/", ::http::Method::GET, &[]);
		assert_eq!(pol.request_hash(&req), None);
	}
}
