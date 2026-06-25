//! Method-aware MCP payload traversal, decoupled from the guardrail that decides
//! verdicts. Non-list methods are flattened to a list of editable [`TextSlot`]s
//! (text + location); a driver runs over the slot texts (via the adapter in
//! [`super::adapter`]) and any rewrites are spliced back with [`apply_replacements`].
//!
//! List responses (`*/list`) flatten to [`EntrySlot`]s instead: every entry's
//! name/title/description is scanned by the same driver, and any entry the driver
//! rewrites or rejects is dropped via [`drop_list_entries`].

use std::collections::HashSet;

use serde_json::Value;

use super::methods;

/// An editable text leaf and where it lives in the JSON document.
pub(crate) struct TextSlot {
	pub location: Vec<PathSeg>,
	pub text: String,
}

/// A text field of a `*/list` entry, tagged with the entry's array index so a
/// driver hit on any of an entry's fields can drop the whole entry.
pub(crate) struct EntrySlot {
	pub entry: usize,
	pub text: String,
}

#[derive(Clone)]
pub(crate) enum PathSeg {
	Key(&'static str),
	OwnedKey(String),
	Index(usize),
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

/// Whether the response for `method` is a fanout list filtered per-entry rather
/// than flattened to slots.
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

/// Flatten the editable text in a request body (non-list methods only).
pub(crate) fn extract_request(method: &str, params: &Value) -> Vec<TextSlot> {
	let mut c = Collector { slots: Vec::new() };
	c.request(method, params);
	c.slots
}

/// Flatten the editable text in a response body. List methods produce no slots
/// here — use [`extract_list_entries`] for those.
pub(crate) fn extract_response(method: &str, result: &Value) -> Vec<TextSlot> {
	let mut c = Collector { slots: Vec::new() };
	c.response(method, result);
	c.slots
}

struct Collector {
	slots: Vec<TextSlot>,
}

impl Collector {
	fn request(&mut self, method: &str, params: &Value) {
		match method {
			methods::TOOLS_CALL | methods::PROMPTS_GET => {
				if let Some(args) = params.get("arguments") {
					self.walk(args, &PathNode::Root.key("arguments"));
				}
			},
			methods::RESOURCES_READ => self.field(params, "uri", &PathNode::Root),
			_ => {},
		}
	}

	fn response(&mut self, method: &str, result: &Value) {
		let root = PathNode::Root;
		match method {
			methods::TOOLS_CALL => {
				let content = root.key("content");
				for (i, item) in content_array_iter(result, "content") {
					self.content_block(item, &content.index(i));
				}
				if let Some(sc) = result.get("structuredContent") {
					self.walk(sc, &root.key("structuredContent"));
				}
			},
			methods::RESOURCES_READ => {
				let contents = root.key("contents");
				for (i, item) in content_array_iter(result, "contents") {
					self.field(item, "text", &contents.index(i));
				}
			},
			methods::PROMPTS_GET => {
				self.field(result, "description", &root);
				let messages = root.key("messages");
				for (i, m) in content_array_iter(result, "messages") {
					if let Some(content) = m.get("content") {
						self.content_block(content, &messages.index(i).key("content"));
					}
				}
			},
			// `*/list` is handled by `extract_list_entries` + `drop_list_entries`.
			_ => {},
		}
	}

	fn push(&mut self, text: &str, node: &PathNode) {
		self.slots.push(TextSlot {
			location: node.to_path(),
			text: text.to_string(),
		});
	}

	fn field(&mut self, obj: &Value, key: &'static str, node: &PathNode) {
		if let Some(Value::String(s)) = obj.get(key) {
			self.push(s, &node.key(key));
		}
	}

	fn walk(&mut self, value: &Value, node: &PathNode) {
		match value {
			Value::String(s) => self.push(s, node),
			Value::Object(map) => {
				for (k, v) in map {
					self.walk(v, &node.borrowed_key(k));
				}
			},
			Value::Array(arr) => {
				for (i, v) in arr.iter().enumerate() {
					self.walk(v, &node.index(i));
				}
			},
			_ => {},
		}
	}

	fn content_block(&mut self, block: &Value, base: &PathNode) {
		match block.get("type").and_then(Value::as_str) {
			Some("text") => self.field(block, "text", base),
			Some("resource") => {
				if let Some(res) = block.get("resource") {
					self.field(res, "text", &base.key("resource"));
					if let Some(contents) = res.get("resource") {
						self.field(contents, "text", &base.key("resource").key("resource"));
					}
				}
			},
			Some("resource_link") => {
				for key in ["name", "title", "description"] {
					self.field(block, key, base);
				}
			},
			_ => {},
		}
	}
}

/// Flatten the non-empty name/title/description of every `*/list` entry, each
/// tagged with its entry index.
pub(crate) fn extract_list_entries(method: &str, result: &Value) -> Vec<EntrySlot> {
	let Some(field) = list_field(method) else {
		return Vec::new();
	};
	let Some(entries) = result.get(field).and_then(Value::as_array) else {
		return Vec::new();
	};
	let mut slots = Vec::new();
	for (entry, item) in entries.iter().enumerate() {
		for key in ["name", "title", "description"] {
			if let Some(Value::String(s)) = item.get(key) {
				if !s.is_empty() {
					slots.push(EntrySlot {
						entry,
						text: s.clone(),
					});
				}
			}
		}
	}
	slots
}

/// Remove the given entry indices from a `*/list` array in a single pass.
pub(crate) fn drop_list_entries(method: &str, result: &mut Value, drop: &HashSet<usize>) {
	let Some(field) = list_field(method) else {
		return;
	};
	let Some(arr) = result.get_mut(field).and_then(Value::as_array_mut) else {
		return;
	};
	let mut index = 0;
	arr.retain(|_| {
		let keep = !drop.contains(&index);
		index += 1;
		keep
	});
}

fn content_array_iter<'a>(obj: &'a Value, field: &str) -> impl Iterator<Item = (usize, &'a Value)> {
	obj
		.get(field)
		.and_then(Value::as_array)
		.into_iter()
		.flat_map(|a| a.iter().enumerate())
}

/// Splice rewritten leaf texts back into `value` at their recorded locations.
pub(crate) fn apply_replacements(value: &mut Value, replacements: Vec<(Vec<PathSeg>, String)>) {
	for (path, new) in replacements {
		if let Some(slot) = navigate_mut(value, &path) {
			*slot = Value::String(new);
		}
	}
}

fn navigate_mut<'v>(root: &'v mut Value, path: &[PathSeg]) -> Option<&'v mut Value> {
	let mut cur = root;
	for seg in path {
		cur = match seg {
			PathSeg::Key(k) => cur.get_mut(*k)?,
			PathSeg::OwnedKey(k) => cur.get_mut(k)?,
			PathSeg::Index(i) => cur.get_mut(*i)?,
		};
	}
	Some(cur)
}

enum PathNode<'a> {
	Root,
	Child {
		parent: &'a PathNode<'a>,
		step: Step<'a>,
	},
}

enum Step<'a> {
	Key(&'static str),
	BorrowedKey(&'a str),
	Index(usize),
}

impl<'a> PathNode<'a> {
	fn key(&'a self, key: &'static str) -> PathNode<'a> {
		PathNode::Child {
			parent: self,
			step: Step::Key(key),
		}
	}

	fn borrowed_key(&'a self, key: &'a str) -> PathNode<'a> {
		PathNode::Child {
			parent: self,
			step: Step::BorrowedKey(key),
		}
	}

	fn index(&'a self, index: usize) -> PathNode<'a> {
		PathNode::Child {
			parent: self,
			step: Step::Index(index),
		}
	}

	fn to_path(&self) -> Vec<PathSeg> {
		let mut out = Vec::new();
		self.write(&mut out);
		out
	}

	fn write(&self, out: &mut Vec<PathSeg>) {
		if let PathNode::Child { parent, step } = self {
			parent.write(out);
			out.push(match step {
				Step::Key(k) => PathSeg::Key(k),
				Step::BorrowedKey(k) => PathSeg::OwnedKey(k.to_string()),
				Step::Index(i) => PathSeg::Index(*i),
			});
		}
	}
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	fn texts(slots: &[TextSlot]) -> Vec<String> {
		let mut v: Vec<String> = slots.iter().map(|s| s.text.clone()).collect();
		v.sort_unstable();
		v
	}

	#[test]
	fn request_tools_call_walks_arguments() {
		let params = json!({"name": "echo", "arguments": {"note": "hi", "n": 3, "nested": {"k": "v"}}});
		assert_eq!(
			texts(&extract_request(methods::TOOLS_CALL, &params)),
			vec!["hi", "v"]
		);
	}

	#[test]
	fn request_resources_read_uri() {
		let params = json!({"uri": "file:///secret"});
		assert_eq!(
			texts(&extract_request(methods::RESOURCES_READ, &params)),
			vec!["file:///secret"]
		);
	}

	#[test]
	fn response_tools_call_scans_text_resource_and_link() {
		let result = json!({
			"content": [
				{"type": "text", "text": "leak"},
				{"type": "image", "data": "AAAA", "mimeType": "image/png"},
				{"type": "resource", "resource": {"uri": "file://x", "text": "embedded leak"}},
				{"type": "resource", "resource": {"uri": "file://y", "blob": "AAAA"}},
				{"type": "resource_link", "uri": "file://z", "name": "linkname", "description": "linkdesc"},
			],
			"structuredContent": {"field": "deep"},
		});
		assert_eq!(
			texts(&extract_response(methods::TOOLS_CALL, &result)),
			vec!["deep", "embedded leak", "leak", "linkdesc", "linkname"]
		);
	}

	#[test]
	fn response_prompts_get_scans_embedded_resource() {
		let result = json!({
			"description": "top-level leak",
			"messages": [
				{"role": "user", "content": {"type": "text", "text": "plain"}},
				{"role": "user", "content": {
					"type": "resource",
					"resource": {"resource": {"uri": "u", "text": "res leak"}}
				}},
			],
		});
		assert_eq!(
			texts(&extract_response(methods::PROMPTS_GET, &result)),
			vec!["plain", "res leak", "top-level leak"]
		);
	}

	#[test]
	fn list_methods_produce_no_flat_slots() {
		let result = json!({"tools": [{"name": "a", "description": "does a"}]});
		assert!(extract_response(methods::TOOLS_LIST, &result).is_empty());
	}

	#[test]
	fn apply_replacements_rewrites_nested_path() {
		let mut result = json!({"content": [], "structuredContent": {"a": {"b": "secret"}}});
		let slots = extract_response(methods::TOOLS_CALL, &result);
		let slot = slots
			.into_iter()
			.find(|s| s.text == "secret")
			.expect("secret slot");
		apply_replacements(&mut result, vec![(slot.location, "<m>".to_string())]);
		assert_eq!(result["structuredContent"]["a"]["b"], json!("<m>"));
	}

	#[test]
	fn list_entries_flatten_with_index() {
		let result = json!({"tools": [
			{"name": "a", "title": "A title", "description": "does a"},
			{"name": "b"},
		]});
		let slots = extract_list_entries(methods::TOOLS_LIST, &result);
		let mut got: Vec<(usize, String)> = slots.iter().map(|s| (s.entry, s.text.clone())).collect();
		got.sort();
		assert_eq!(
			got,
			vec![
				(0, "A title".to_string()),
				(0, "a".to_string()),
				(0, "does a".to_string()),
				(1, "b".to_string()),
			]
		);
	}

	#[test]
	fn drop_list_entries_high_index_first() {
		let mut result = json!({"tools": [{"name": "a"}, {"name": "b"}, {"name": "c"}]});
		drop_list_entries(methods::TOOLS_LIST, &mut result, &HashSet::from([0, 2]));
		assert_eq!(result["tools"], json!([{"name": "b"}]));
	}
}
