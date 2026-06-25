//! OpenAI Responses API orchestration.
//!
//! Codex and other Responses-API clients carry tool outputs under `input[]` as
//! `function_call_output` / `custom_tool_call_output` items (and prior turns as
//! `message` items) — *not* under chat-completions `messages[]`, so the
//! [`super::completions`] walker sees nothing. Same approach as the other
//! orchestrators: identify model-visible strings, splice compressed strings back
//! into the original bytes, fail-open on any parse/serialize miss.

use super::{dispatch::StrategySet, fragments};

/// Compress eligible tool outputs / message text in an OpenAI Responses body.
/// Returns `Some(new_bytes)` when at least one fragment was rewritten, else
/// `None` (nothing changed, or the body did not parse/serialize — fail-open).
pub fn compress(body: &[u8], strategies: StrategySet) -> Option<Vec<u8>> {
	let walk = fragments::responses_replacements(body, strategies)?;
	fragments::apply_string_replacements(body, walk.replacements)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn big_json_array() -> String {
		let rows: Vec<String> = (0..60)
			.map(|i| format!(r#"{{"id":{i},"name":"item-{i}","status":"ok","detail":"lorem ipsum dolor sit amet consectetur"}}"#))
			.collect();
		format!("[{}]", rows.join(","))
	}

	/// The Codex case: a `function_call_output` with a large JSON string output is
	/// detected + compressed, even though the body has `input`, not `messages`.
	#[test]
	fn compresses_function_call_output() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-5-codex",
			"input": [
				{ "type": "function_call_output", "call_id": "c1", "output": big },
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len());

		// Output is still a well-formed Responses body with a smaller output.
		let root: serde_json::Value = serde_json::from_slice(&out).unwrap();
		let new_out = root["input"][0]["output"].as_str().unwrap();
		assert!(new_out.len() < big.len());
	}

	/// `custom_tool_call_output` is treated the same as `function_call_output`.
	#[test]
	fn compresses_custom_tool_call_output() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-5-codex",
			"input": [
				{ "type": "custom_tool_call_output", "call_id": "c1", "output": big },
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len());
	}

	/// Output given as a list of content parts ({type, text}) — compress the text.
	#[test]
	fn compresses_structured_output_parts() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-5-codex",
			"input": [
				{ "type": "function_call_output", "call_id": "c1", "output": [
					{ "type": "output_text", "text": big }
				]},
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		let out = compress(&bytes, StrategySet::headroom_only()).expect("should compress");
		assert!(out.len() < bytes.len());
	}

	/// A sub-threshold output is left alone (nothing eligible → no change).
	#[test]
	fn noop_below_threshold() {
		let body = serde_json::json!({
			"model": "gpt-5-codex",
			"input": [
				{ "type": "function_call_output", "call_id": "c1", "output": "[{\"id\":1}]" },
			]
		});
		let bytes = serde_json::to_vec(&body).unwrap();
		assert!(compress(&bytes, StrategySet::headroom_only()).is_none());
	}

	/// A chat-completions-shaped body (no `input`) is a clean no-op here.
	#[test]
	fn noop_on_completions_shape() {
		let big = big_json_array();
		let body = serde_json::json!({
			"model": "gpt-4o",
			"messages": [
				{ "role": "tool", "tool_call_id": "t1", "content": big },
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
  "model": "gpt-5-codex",
  "store": true,
  "vendor_field": {{"preserve": true}},
  "input": [
    {{ "type": "function_call_output", "call_id": "c1", "output": {big_json} }}
  ]
}}"#,
			big_json = serde_json::to_string(&big).unwrap()
		);
		let out = compress(body.as_bytes(), StrategySet::headroom_only()).expect("should compress");
		let out = String::from_utf8(out).unwrap();

		assert!(out.contains(r#""vendor_field": {"preserve": true}"#));
		assert!(out.contains(r#""input": ["#));
		assert!(out.len() < body.len());
	}
}
