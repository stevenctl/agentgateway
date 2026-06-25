//! Method-aware MCP payload traversal for in-place text inspection.

use serde_json::Value;

use super::methods;

pub(crate) enum TextDecision {
	Pass,
	Replace(String),
	Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VisitOutcome {
	Pass,
	Mutated,
	Rejected,
}

impl VisitOutcome {
	fn merge(self, other: Self) -> Self {
		match (self, other) {
			(Self::Rejected, _) | (_, Self::Rejected) => Self::Rejected,
			(Self::Mutated, _) | (_, Self::Mutated) => Self::Mutated,
			_ => Self::Pass,
		}
	}
}

pub(crate) fn supports_request(method: &str) -> bool {
	matches!(
		method,
		methods::TOOLS_CALL | methods::PROMPTS_GET | methods::RESOURCES_READ
	)
}

pub(crate) fn supports_response(method: &str) -> bool {
	matches!(
		method,
		methods::TOOLS_CALL
			| methods::PROMPTS_GET
			| methods::RESOURCES_READ
			| methods::TOOLS_LIST
			| methods::PROMPTS_LIST
			| methods::RESOURCES_LIST
			| methods::RESOURCES_TEMPLATES_LIST
	)
}

pub(crate) fn is_list_response(method: &str) -> bool {
	list_field(method).is_some()
}

fn list_field(method: &str) -> Option<&'static str> {
	match method {
		methods::TOOLS_LIST => Some("tools"),
		methods::PROMPTS_LIST => Some("prompts"),
		methods::RESOURCES_LIST => Some("resources"),
		methods::RESOURCES_TEMPLATES_LIST => Some("resourceTemplates"),
		_ => None,
	}
}

pub(crate) fn visit_request(
	method: &str,
	params: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match method {
		methods::TOOLS_CALL | methods::PROMPTS_GET => params
			.get_mut("arguments")
			.map(|arguments| walk(arguments, visit))
			.unwrap_or(VisitOutcome::Pass),
		methods::RESOURCES_READ => field(params, "uri", visit),
		_ => VisitOutcome::Pass,
	}
}

pub(crate) fn visit_response(
	method: &str,
	result: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match method {
		methods::TOOLS_CALL => {
			let mut outcome = content_array(result, "content", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(structured) = result.get_mut("structuredContent") {
					outcome = outcome.merge(walk(structured, visit));
				}
			}
			outcome
		},
		methods::RESOURCES_READ => array_fields(result, "contents", "text", visit),
		methods::PROMPTS_GET => {
			let mut outcome = field(result, "description", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(messages) = result.get_mut("messages").and_then(Value::as_array_mut) {
					for message in messages {
						let Some(content) = message.get_mut("content") else {
							continue;
						};
						outcome = outcome.merge(content_block(content, visit));
						if outcome == VisitOutcome::Rejected {
							break;
						}
					}
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

/// Drop list entries for which any inspected field would be rewritten. A rejection
/// still rejects the entire response.
pub(crate) fn filter_list_entries(
	method: &str,
	result: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(field_name) = list_field(method) else {
		return VisitOutcome::Pass;
	};
	let Some(entries) = result.get_mut(field_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};

	let mut drop = vec![false; entries.len()];
	for (index, entry) in entries.iter().enumerate() {
		for key in ["name", "title", "description"] {
			let Some(text) = entry.get(key).and_then(Value::as_str) else {
				continue;
			};
			match visit(text) {
				TextDecision::Pass => {},
				TextDecision::Replace(_) => {
					drop[index] = true;
					break;
				},
				TextDecision::Reject => return VisitOutcome::Rejected,
			}
		}
	}

	if !drop.iter().any(|drop| *drop) {
		return VisitOutcome::Pass;
	}
	let mut index = 0;
	entries.retain(|_| {
		let keep = !drop[index];
		index += 1;
		keep
	});
	VisitOutcome::Mutated
}

fn apply(text: &mut String, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match visit(text) {
		TextDecision::Pass => VisitOutcome::Pass,
		TextDecision::Replace(replacement) if replacement == *text => VisitOutcome::Pass,
		TextDecision::Replace(replacement) => {
			*text = replacement;
			VisitOutcome::Mutated
		},
		TextDecision::Reject => VisitOutcome::Rejected,
	}
}

fn field(
	value: &mut Value,
	key: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match value.get_mut(key) {
		Some(Value::String(text)) => apply(text, visit),
		_ => VisitOutcome::Pass,
	}
}

fn walk(value: &mut Value, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match value {
		Value::String(text) => apply(text, visit),
		Value::Array(values) => {
			let mut outcome = VisitOutcome::Pass;
			for value in values {
				outcome = outcome.merge(walk(value, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		Value::Object(values) => {
			let mut outcome = VisitOutcome::Pass;
			for value in values.values_mut() {
				outcome = outcome.merge(walk(value, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

fn content_array(
	result: &mut Value,
	field_name: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(contents) = result.get_mut(field_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};
	let mut outcome = VisitOutcome::Pass;
	for content in contents {
		outcome = outcome.merge(content_block(content, visit));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn array_fields(
	result: &mut Value,
	array_name: &str,
	field_name: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(values) = result.get_mut(array_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};
	let mut outcome = VisitOutcome::Pass;
	for value in values {
		outcome = outcome.merge(field(value, field_name, visit));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn content_block(block: &mut Value, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match block.get("type").and_then(Value::as_str) {
		Some("text") => field(block, "text", visit),
		Some("resource") => {
			let Some(resource) = block.get_mut("resource") else {
				return VisitOutcome::Pass;
			};
			let mut outcome = field(resource, "text", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(contents) = resource.get_mut("resource") {
					outcome = outcome.merge(field(contents, "text", visit));
				}
			}
			outcome
		},
		Some("resource_link") => {
			let mut outcome = VisitOutcome::Pass;
			for key in ["name", "title", "description"] {
				outcome = outcome.merge(field(block, key, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	fn replace_secret(text: &str) -> TextDecision {
		if text.contains("secret") {
			TextDecision::Replace(text.replace("secret", "<masked>"))
		} else {
			TextDecision::Pass
		}
	}

	#[test]
	fn request_tools_call_rewrites_nested_arguments() {
		let mut params = json!({
			"name": "echo",
			"arguments": {"note": "secret", "nested": {"value": "another secret"}}
		});
		assert_eq!(
			visit_request(methods::TOOLS_CALL, &mut params, &mut replace_secret),
			VisitOutcome::Mutated
		);
		assert_eq!(params["arguments"]["note"], json!("<masked>"));
		assert_eq!(
			params["arguments"]["nested"]["value"],
			json!("another <masked>")
		);
	}

	#[test]
	fn response_tools_call_rewrites_supported_content() {
		let mut result = json!({
			"content": [
				{"type": "text", "text": "secret"},
				{"type": "image", "data": "secret", "mimeType": "image/png"},
				{"type": "resource", "resource": {"uri": "file://x", "text": "embedded secret"}},
				{"type": "resource_link", "uri": "file://z", "name": "secret link"},
			],
			"structuredContent": {"field": "deep secret"},
		});
		assert_eq!(
			visit_response(methods::TOOLS_CALL, &mut result, &mut replace_secret),
			VisitOutcome::Mutated
		);
		assert_eq!(result["content"][0]["text"], json!("<masked>"));
		assert_eq!(result["content"][1]["data"], json!("secret"));
		assert_eq!(
			result["content"][2]["resource"]["text"],
			json!("embedded <masked>")
		);
		assert_eq!(result["content"][3]["name"], json!("<masked> link"));
		assert_eq!(result["structuredContent"]["field"], json!("deep <masked>"));
	}

	#[test]
	fn response_prompts_get_rewrites_description_and_resource() {
		let mut result = json!({
			"description": "secret prompt",
			"messages": [{
				"role": "user",
				"content": {
					"type": "resource",
					"resource": {"resource": {"uri": "u", "text": "secret resource"}}
				}
			}],
		});
		assert_eq!(
			visit_response(methods::PROMPTS_GET, &mut result, &mut replace_secret),
			VisitOutcome::Mutated
		);
		assert_eq!(result["description"], json!("<masked> prompt"));
		assert_eq!(
			result["messages"][0]["content"]["resource"]["resource"]["text"],
			json!("<masked> resource")
		);
	}

	#[test]
	fn list_entries_with_matches_are_dropped() {
		let mut result = json!({"tools": [
			{"name": "safe", "description": "ok"},
			{"name": "secret_tool", "description": "not returned"},
			{"name": "also-safe", "description": "contains secret"},
		]});
		assert_eq!(
			filter_list_entries(methods::TOOLS_LIST, &mut result, &mut replace_secret),
			VisitOutcome::Mutated
		);
		assert_eq!(
			result["tools"],
			json!([{"name": "safe", "description": "ok"}])
		);
	}

	#[test]
	fn rejection_short_circuits() {
		let mut params = json!({"arguments": {"first": "reject", "second": "secret"}});
		let mut reject = |text: &str| {
			if text == "reject" {
				TextDecision::Reject
			} else {
				replace_secret(text)
			}
		};
		assert_eq!(
			visit_request(methods::TOOLS_CALL, &mut params, &mut reject),
			VisitOutcome::Rejected
		);
	}
}
