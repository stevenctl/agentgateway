//! OpenAI / OpenAI-compatible Chat Completions orchestration.
//!
//! Same idea as [`super::anthropic`], different request shape. We identify
//! model-visible strings in messages, then splice compressed strings into the
//! original bytes. We compress them **from first sight, including the latest
//! turn** — headroom is gateway-decided and structural, so nothing waits on the
//! model and determinism keeps the bytes stable across turns. (See the
//! [`super::anthropic`] note on why metamem differs.)

use super::{dispatch::StrategySet, fragments};

/// Compress eligible `role: "tool"` messages in an OpenAI-shaped Chat Completions
/// body. Returns `Some(new_bytes)` when at least one was rewritten, else `None`
/// (nothing changed, or the body did not parse/serialize — fail-open).
pub fn compress(body: &[u8], strategies: StrategySet) -> Option<Vec<u8>> {
	let walk = fragments::completions_replacements(body, strategies)?;
	fragments::apply_string_replacements(body, walk.replacements)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::llm::types::completions::typed::{
		Request, RequestMessage, RequestToolMessage, RequestToolMessageContent,
	};

	fn big_json_array() -> String {
		let rows: Vec<String> = (0..60)
			.map(|i| format!(r#"{{"id":{i},"name":"item-{i}","status":"ok","detail":"lorem ipsum dolor sit amet consectetur"}}"#))
			.collect();
		format!("[{}]", rows.join(","))
	}

	/// Compress from first sight: even a single-message body (the latest turn)
	/// gets its tool output compressed.
	#[test]
	fn compresses_latest_tool_message() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-4o",
			"messages": [
				{ "role": "tool", "tool_call_id": "t1", "content": big },
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len());

		let reparsed: Request = serde_json::from_slice(&out).unwrap();
		let RequestMessage::Tool(RequestToolMessage {
			content: RequestToolMessageContent::Text(t),
			..
		}) = &reparsed.messages[0]
		else {
			panic!("expected tool message text");
		};
		assert!(t.len() < big.len());
	}

	/// A sub-threshold tool message is left alone (nothing eligible → no change).
	#[test]
	fn noop_below_threshold() {
		let body = serde_json::json!({
			"model": "gpt-4o",
			"messages": [
				{ "role": "tool", "tool_call_id": "t1", "content": "[{\"id\":1}]" },
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
  "model": "gpt-4o",
  "store": true,
  "vendor_field": {{"preserve": true}},
  "messages": [
    {{ "role": "tool", "tool_call_id": "t1", "content": {big_json} }}
  ]
}}"#,
			big_json = serde_json::to_string(&big).unwrap()
		);
		let out = compress(body.as_bytes(), StrategySet::headroom_only()).expect("should compress");
		let out = String::from_utf8(out).unwrap();

		assert!(out.contains(r#""vendor_field": {"preserve": true}"#));
		assert!(out.contains(r#""messages": ["#));
		assert!(out.len() < body.len());
	}

	#[test]
	fn compresses_non_tool_message_text_when_structured() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-4o",
			"messages": [
				{ "role": "user", "content": [
					{ "type": "text", "text": big }
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
			"model": "gpt-4o",
			"messages": [
				{ "role": "user", "content": text },
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
