use std::cmp::Reverse;
use std::ops::ControlFlow;

use serde_json::Value;

use super::methods;

pub(crate) enum LeafVerdict {
	Clean,
	Masked(String),
	Rejected,
}

pub(crate) enum Scan {
	Pass,
	Reject,
	Edits(Vec<(SlotLocation, Edit)>),
}

pub(crate) enum SlotLocation {
	Path(Vec<PathSeg>),
	ListEntry { field: &'static str, index: usize },
}

#[derive(Clone)]
pub(crate) enum PathSeg {
	Key(&'static str),
	OwnedKey(String),
	Index(usize),
}

pub(crate) enum Edit {
	Replace(String),
	Drop,
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

pub(crate) fn scan_request<F: FnMut(&str) -> LeafVerdict>(
	method: &str,
	params: &Value,
	visit: &mut F,
) -> Scan {
	let mut s = Scanner {
		visit,
		edits: Vec::new(),
	};
	let flow = s_request(&mut s, method, params);
	s.finish(flow)
}

pub(crate) fn scan_response<F: FnMut(&str) -> LeafVerdict>(
	method: &str,
	result: &Value,
	visit: &mut F,
) -> Scan {
	let mut s = Scanner {
		visit,
		edits: Vec::new(),
	};
	let flow = s_response(&mut s, method, result);
	s.finish(flow)
}

fn s_request<F: FnMut(&str) -> LeafVerdict>(
	s: &mut Scanner<'_, F>,
	method: &str,
	params: &Value,
) -> ControlFlow<()> {
	match method {
		methods::TOOLS_CALL | methods::PROMPTS_GET => {
			if let Some(args) = params.get("arguments") {
				s.walk(args, &PathNode::Root.key("arguments"))?;
			}
		},
		methods::RESOURCES_READ => s.field(params, "uri", &PathNode::Root)?,
		_ => {},
	}
	ControlFlow::Continue(())
}

fn s_response<F: FnMut(&str) -> LeafVerdict>(
	s: &mut Scanner<'_, F>,
	method: &str,
	result: &Value,
) -> ControlFlow<()> {
	let root = PathNode::Root;
	match method {
		methods::TOOLS_CALL => {
			let content = root.key("content");
			for (i, item) in content_array_iter(result, "content") {
				s.content_block(item, &content.index(i))?;
			}
			if let Some(sc) = result.get("structuredContent") {
				s.walk(sc, &root.key("structuredContent"))?;
			}
		},
		methods::RESOURCES_READ => {
			let contents = root.key("contents");
			for (i, item) in content_array_iter(result, "contents") {
				s.field(item, "text", &contents.index(i))?;
			}
		},
		methods::PROMPTS_GET => {
			let messages = root.key("messages");
			for (i, m) in content_array_iter(result, "messages") {
				if let Some(content) = m.get("content") {
					s.content_block(content, &messages.index(i).key("content"))?;
				}
			}
		},
		methods::TOOLS_LIST => s.list_entries(result, "tools")?,
		methods::PROMPTS_LIST => s.list_entries(result, "prompts")?,
		methods::RESOURCES_LIST => s.list_entries(result, "resources")?,
		methods::RESOURCES_TEMPLATES_LIST => s.list_entries(result, "resourceTemplates")?,
		_ => {},
	}
	ControlFlow::Continue(())
}

fn content_array_iter<'a>(obj: &'a Value, field: &str) -> impl Iterator<Item = (usize, &'a Value)> {
	obj
		.get(field)
		.and_then(Value::as_array)
		.into_iter()
		.flat_map(|a| a.iter().enumerate())
}

struct Scanner<'f, F> {
	visit: &'f mut F,
	edits: Vec<(SlotLocation, Edit)>,
}

impl<F: FnMut(&str) -> LeafVerdict> Scanner<'_, F> {
	fn finish(self, flow: ControlFlow<()>) -> Scan {
		match flow {
			ControlFlow::Break(()) => Scan::Reject,
			ControlFlow::Continue(()) if self.edits.is_empty() => Scan::Pass,
			ControlFlow::Continue(()) => Scan::Edits(self.edits),
		}
	}

	fn editable(&mut self, text: &str, node: &PathNode) -> ControlFlow<()> {
		match (self.visit)(text) {
			LeafVerdict::Clean => ControlFlow::Continue(()),
			LeafVerdict::Rejected => ControlFlow::Break(()),
			LeafVerdict::Masked(new) => {
				self
					.edits
					.push((SlotLocation::Path(node.to_path()), Edit::Replace(new)));
				ControlFlow::Continue(())
			},
		}
	}

	fn field(&mut self, obj: &Value, key: &'static str, node: &PathNode) -> ControlFlow<()> {
		if let Some(Value::String(s)) = obj.get(key) {
			self.editable(s, &node.key(key))?;
		}
		ControlFlow::Continue(())
	}

	fn walk(&mut self, value: &Value, node: &PathNode) -> ControlFlow<()> {
		match value {
			Value::String(s) => self.editable(s, node)?,
			Value::Object(map) => {
				for (k, v) in map {
					self.walk(v, &node.borrowed_key(k))?;
				}
			},
			Value::Array(arr) => {
				for (i, v) in arr.iter().enumerate() {
					self.walk(v, &node.index(i))?;
				}
			},
			_ => {},
		}
		ControlFlow::Continue(())
	}

	fn content_block(&mut self, block: &Value, base: &PathNode) -> ControlFlow<()> {
		match block.get("type").and_then(Value::as_str) {
			Some("text") => self.field(block, "text", base)?,
			Some("resource") => {
				if let Some(res) = block.get("resource") {
					self.field(res, "text", &base.key("resource"))?;
					if let Some(contents) = res.get("resource") {
						self.field(contents, "text", &base.key("resource").key("resource"))?;
					}
				}
			},
			Some("resource_link") => {
				for key in ["name", "title", "description"] {
					self.field(block, key, base)?;
				}
			},
			_ => {},
		}
		ControlFlow::Continue(())
	}

	fn list_entries(&mut self, result: &Value, field: &'static str) -> ControlFlow<()> {
		let Some(Value::Array(entries)) = result.get(field) else {
			return ControlFlow::Continue(());
		};
		for (index, entry) in entries.iter().enumerate() {
			let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
			let desc = entry
				.get("description")
				.and_then(Value::as_str)
				.unwrap_or("");
			let title = entry.get("title").and_then(Value::as_str).unwrap_or("");
			if name.is_empty() && title.is_empty() && desc.is_empty() {
				continue;
			}
			let mut matched = false;
			for text in [name, title, desc] {
				if text.is_empty() {
					continue;
				}
				match (self.visit)(text) {
					LeafVerdict::Clean => {},
					LeafVerdict::Rejected => return ControlFlow::Break(()),
					LeafVerdict::Masked(_) => matched = true,
				}
			}
			if matched {
				self
					.edits
					.push((SlotLocation::ListEntry { field, index }, Edit::Drop));
			}
		}
		ControlFlow::Continue(())
	}
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

pub(crate) fn apply_edits(value: &mut Value, edits: Vec<(SlotLocation, Edit)>) {
	let mut drops: Vec<(&'static str, usize)> = Vec::new();
	for (loc, edit) in edits {
		match (loc, edit) {
			(SlotLocation::Path(path), Edit::Replace(new)) => {
				if let Some(slot) = navigate_mut(value, &path) {
					*slot = Value::String(new);
				}
			},
			(SlotLocation::ListEntry { field, index }, _) => drops.push((field, index)),
			(SlotLocation::Path(_), Edit::Drop) => {},
		}
	}
	drops.sort_unstable_by_key(|drop| Reverse(drop.1));
	for (field, index) in drops {
		if let Some(Value::Array(arr)) = value.get_mut(field)
			&& index < arr.len()
		{
			arr.remove(index);
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

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	fn recorder(seen: &mut Vec<String>) -> impl FnMut(&str) -> LeafVerdict + '_ {
		|t: &str| {
			seen.push(t.to_string());
			LeafVerdict::Clean
		}
	}

	fn scanned_request(method: &str, params: &Value) -> Vec<String> {
		let mut seen = Vec::new();
		let _ = scan_request(method, params, &mut recorder(&mut seen));
		seen.sort_unstable();
		seen
	}

	fn scanned_response(method: &str, result: &Value) -> Vec<String> {
		let mut seen = Vec::new();
		let _ = scan_response(method, result, &mut recorder(&mut seen));
		seen.sort_unstable();
		seen
	}

	fn mask_containing(needle: &'static str) -> impl FnMut(&str) -> LeafVerdict {
		move |t: &str| {
			if t.contains(needle) {
				LeafVerdict::Masked("<m>".into())
			} else {
				LeafVerdict::Clean
			}
		}
	}

	#[test]
	fn request_tools_call_walks_arguments() {
		let params = json!({"name": "echo", "arguments": {"note": "hi", "n": 3, "nested": {"k": "v"}}});
		assert_eq!(
			scanned_request(methods::TOOLS_CALL, &params),
			vec!["hi", "v"]
		);
	}

	#[test]
	fn request_resources_read_uri() {
		let params = json!({"uri": "file:///secret"});
		assert_eq!(
			scanned_request(methods::RESOURCES_READ, &params),
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
			scanned_response(methods::TOOLS_CALL, &result),
			vec!["deep", "embedded leak", "leak", "linkdesc", "linkname"]
		);
	}

	#[test]
	fn response_prompts_get_scans_embedded_resource() {
		let result = json!({"messages": [
			{"role": "user", "content": {"type": "text", "text": "plain"}},
			{"role": "user", "content": {
				"type": "resource",
				"resource": {"resource": {"uri": "u", "text": "res leak"}}
			}},
		]});
		assert_eq!(
			scanned_response(methods::PROMPTS_GET, &result),
			vec!["plain", "res leak"]
		);
	}

	#[test]
	fn response_list_scans_name_and_description() {
		let result = json!({"tools": [
			{"name": "a", "title": "A title", "description": "does a"},
			{"name": "b"}
		]});
		assert_eq!(
			scanned_response(methods::TOOLS_LIST, &result),
			vec!["A title", "a", "b", "does a"]
		);
	}

	#[test]
	fn match_materializes_nested_path() {
		let result = json!({"content": [], "structuredContent": {"a": {"b": "secret"}}});
		let Scan::Edits(edits) =
			scan_response(methods::TOOLS_CALL, &result, &mut mask_containing("secret"))
		else {
			panic!("expected edits");
		};
		let mut v = result.clone();
		apply_edits(&mut v, edits);
		assert_eq!(v["structuredContent"]["a"]["b"], json!("<m>"));
	}

	#[test]
	fn list_match_drops_entry() {
		let result = json!({"tools": [{"name": "a", "description": "does a"}, {"name": "b"}]});
		let Scan::Edits(edits) =
			scan_response(methods::TOOLS_LIST, &result, &mut mask_containing("does a"))
		else {
			panic!("expected edits");
		};
		assert_eq!(edits.len(), 1);
		assert!(matches!(
			edits[0],
			(
				SlotLocation::ListEntry {
					field: "tools",
					index: 0
				},
				Edit::Drop
			)
		));
	}

	#[test]
	fn reject_short_circuits() {
		let params = json!({"arguments": {"a": "x", "b": "y"}});
		assert!(matches!(
			scan_request(methods::TOOLS_CALL, &params, &mut |_: &str| {
				LeafVerdict::Rejected
			}),
			Scan::Reject
		));
	}

	#[test]
	fn no_match_is_pass() {
		let params = json!({"arguments": {"a": "x"}});
		assert!(matches!(
			scan_request(methods::TOOLS_CALL, &params, &mut |_: &str| {
				LeafVerdict::Clean
			}),
			Scan::Pass
		));
	}

	#[test]
	fn apply_edits_replaces_leaf() {
		let mut result = json!({"content": [{"type": "text", "text": "leak"}]});
		let edits = vec![(
			SlotLocation::Path(vec![
				PathSeg::Key("content"),
				PathSeg::Index(0),
				PathSeg::Key("text"),
			]),
			Edit::Replace("<masked>".into()),
		)];
		apply_edits(&mut result, edits);
		assert_eq!(result["content"][0]["text"], json!("<masked>"));
	}

	#[test]
	fn apply_edits_drops_entries_high_index_first() {
		let mut result = json!({"tools": [{"name": "a"}, {"name": "b"}, {"name": "c"}]});
		let edits = vec![
			(
				SlotLocation::ListEntry {
					field: "tools",
					index: 0,
				},
				Edit::Drop,
			),
			(
				SlotLocation::ListEntry {
					field: "tools",
					index: 2,
				},
				Edit::Drop,
			),
		];
		apply_edits(&mut result, edits);
		assert_eq!(result["tools"], json!([{"name": "b"}]));
	}
}
