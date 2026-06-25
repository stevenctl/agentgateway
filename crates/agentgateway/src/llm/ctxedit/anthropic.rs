//! Anthropic `/v1/messages` orchestration — our walk, not headroom's LiveZone.
//!
//! Parse enough request structure to identify model-visible text fragments, then
//! splice compressed strings into the original bytes. We compress **from first
//! sight, including the latest turn**: headroom is gateway-decided and
//! structural/statistical, so nothing waits on the model's judgment and there's
//! no reason to ever show it the uncompressed form. Because compression is
//! deterministic, a fragment's bytes are identical the first time it's seen and
//! every turn after — so the cached prefix is byte-stable and each fragment is
//! cache-written once (no double-write).
//!
//! (Contrast metamem, which holds the latest turn uncompressed *because the model
//! is the decider* and must see the original to choose — that's where the
//! freeze-floor / volatile-tail machinery comes from. It does not apply here.)

use super::{dispatch::StrategySet, fragments};

/// Compress eligible tool results in an Anthropic Messages body.
///
/// Returns `Some(new_bytes)` when at least one block was rewritten, `None` when
/// nothing changed or the body could not be parsed/serialized (fail-open: the
/// caller forwards the original bytes).
pub fn compress(body: &[u8], strategies: StrategySet) -> Option<Vec<u8>> {
	let walk = fragments::anthropic_replacements(body, strategies)?;
	fragments::apply_string_replacements(body, walk.replacements)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::llm::types::messages::typed::{ContentBlock, Request, ToolResultContent};

	fn big_json_array() -> String {
		let rows: Vec<String> = (0..60)
			.map(|i| format!(r#"{{"id":{i},"name":"item-{i}","status":"ok","detail":"lorem ipsum dolor sit amet consectetur"}}"#))
			.collect();
		format!("[{}]", rows.join(","))
	}

	/// We compress from first sight: even a single-message body (the latest turn)
	/// gets its tool_result compressed — headroom is gateway-decided, so there's
	/// no "let the model see it first".
	#[test]
	fn compresses_latest_tool_result() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "claude-3-5-sonnet-20241022",
			"max_tokens": 1024,
			"messages": [
				{ "role": "user", "content": [
					{ "type": "tool_result", "tool_use_id": "t1", "content": big }
				]},
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len(), "output should be smaller");

		let reparsed: Request = serde_json::from_slice(&out).unwrap();
		let ContentBlock::ToolResult {
			content: ToolResultContent::Text(t),
			..
		} = &reparsed.messages[0].content[0]
		else {
			panic!("expected tool_result text");
		};
		assert!(t.len() < big.len());
	}

	/// A sub-threshold tool_result is left alone (nothing eligible → no change).
	#[test]
	fn noop_below_threshold() {
		let body = serde_json::json!({
			"model": "claude-3-5-sonnet-20241022",
			"max_tokens": 1024,
			"messages": [
				{ "role": "user", "content": [
					{ "type": "tool_result", "tool_use_id": "t1", "content": "[{\"id\":1}]" }
				]},
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		assert!(compress(&bytes, StrategySet::headroom_only()).is_none());
	}

	#[test]
	fn preserves_unknown_fields_and_original_layout() {
		let big = big_json_array();
		let body = format!(
			r#"{{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 1024,
  "unknown_beta": {{"preserve": true}},
  "messages": [
    {{ "role": "user", "content": [
      {{ "type": "tool_result", "tool_use_id": "t1", "content": {big_json} }}
    ]}}
  ]
}}"#,
			big_json = serde_json::to_string(&big).unwrap()
		);
		let out = compress(body.as_bytes(), StrategySet::headroom_only()).expect("should compress");
		let out = String::from_utf8(out).unwrap();

		assert!(out.contains(r#""unknown_beta": {"preserve": true}"#));
		assert!(out.contains(r#""messages": ["#));
		assert!(out.len() < body.len());
	}

	#[test]
	fn compresses_structured_text_part() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "claude-3-5-sonnet-20241022",
			"max_tokens": 1024,
			"messages": [
				{ "role": "user", "content": [
					{ "type": "tool_result", "tool_use_id": "t1", "content": [
						{ "type": "text", "text": big }
					]}
				]},
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len());
	}

	#[test]
	fn compresses_json_object_with_gcf() {
		let text = serde_json::json!({
			"items": (0..80).map(|i| serde_json::json!({"id": i, "status": "ok"})).collect::<Vec<_>>()
		})
		.to_string();
		let body = serde_json::json!({
			"model": "claude-3-5-sonnet-20241022",
			"max_tokens": 1024,
			"messages": [
				{ "role": "user", "content": [
					{ "type": "text", "text": text }
				]},
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(
			&bytes,
			StrategySet {
				headroom: false,
				gcf: true,
			},
		)
		.expect("should compress");
		assert!(out.len() < bytes.len());
	}
}
