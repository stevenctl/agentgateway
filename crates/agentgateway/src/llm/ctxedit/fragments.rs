//! Fragment extraction and byte-preserving JSON string replacement.
//!
//! The extraction pass is allowed to parse into `serde_json::Value` because it
//! only decides which model-visible strings are eligible. The rewrite pass then
//! scans the original JSON bytes and replaces exactly those string literals,
//! preserving every other byte of the provider request.

use serde_json::Value;

use super::dispatch::{self, StrategySet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathItem {
	Key(String),
	Index(usize),
}

#[derive(Debug)]
struct Replacement {
	path: Vec<PathItem>,
	encoded: Vec<u8>,
}

#[derive(Debug)]
struct SpanReplacement {
	start: usize,
	end: usize,
	encoded: Vec<u8>,
}

/// Per-request walk accounting. `walked` counts every model-visible string the
/// walker visited; `eligible` how many cleared the size threshold; and
/// `replacements` the fragments that actually compressed. Surfacing all three
/// lets the egress path log "walked N, eligible M, compressed K" even when
/// nothing fired — so a quiet run is provably "walker ran, nothing compressible"
/// rather than "walker never reached".
#[derive(Debug, Default)]
pub struct Walk {
	pub replacements: Vec<(Vec<PathItem>, String)>,
	pub walked: usize,
	pub eligible: usize,
}

pub fn anthropic_replacements(body: &[u8], strategies: StrategySet) -> Option<Walk> {
	let root: Value = serde_json::from_slice(body).ok()?;
	let messages = root.get("messages")?.as_array()?;
	let mut w = Walk::default();

	for (msg_idx, msg) in messages.iter().enumerate() {
		let mut msg_path = vec![
			PathItem::Key("messages".to_string()),
			PathItem::Index(msg_idx),
		];
		let Some(content) = msg.get("content") else {
			continue;
		};
		msg_path.push(PathItem::Key("content".to_string()));
		match content {
			Value::String(text) => maybe_push(&mut w, &msg_path, text, strategies),
			Value::Array(blocks) => {
				for (block_idx, block) in blocks.iter().enumerate() {
					let mut block_path = msg_path.clone();
					block_path.push(PathItem::Index(block_idx));
					collect_anthropic_block(&mut w, &block_path, block, strategies);
				}
			},
			_ => {},
		}
	}

	Some(w)
}

fn collect_anthropic_block(
	w: &mut Walk,
	path: &[PathItem],
	block: &Value,
	strategies: StrategySet,
) {
	let block_type = block.get("type").and_then(Value::as_str);
	match block_type {
		Some("text") => collect_key(w, path, block, "text", strategies),
		Some("tool_result") => {
			let mut content_path = path.to_vec();
			content_path.push(PathItem::Key("content".to_string()));
			match block.get("content") {
				Some(Value::String(text)) => maybe_push(w, &content_path, text, strategies),
				Some(Value::Array(parts)) => collect_text_parts(w, &content_path, parts, strategies),
				_ => {},
			}
		},
		Some("document") => collect_key(w, path, block, "context", strategies),
		Some("search_result") => {
			let mut content_path = path.to_vec();
			content_path.push(PathItem::Key("content".to_string()));
			if let Some(Value::Array(parts)) = block.get("content") {
				collect_text_parts(w, &content_path, parts, strategies);
			}
		},
		_ => {},
	}
}

pub fn completions_replacements(body: &[u8], strategies: StrategySet) -> Option<Walk> {
	let root: Value = serde_json::from_slice(body).ok()?;
	let messages = root.get("messages")?.as_array()?;
	let mut w = Walk::default();

	for (msg_idx, msg) in messages.iter().enumerate() {
		let content_path = vec![
			PathItem::Key("messages".to_string()),
			PathItem::Index(msg_idx),
			PathItem::Key("content".to_string()),
		];
		match msg.get("content") {
			Some(Value::String(text)) => maybe_push(&mut w, &content_path, text, strategies),
			Some(Value::Array(parts)) => collect_text_parts(&mut w, &content_path, parts, strategies),
			_ => {},
		}
	}

	Some(w)
}

pub fn responses_replacements(body: &[u8], strategies: StrategySet) -> Option<Walk> {
	let root: Value = serde_json::from_slice(body).ok()?;
	// Responses bodies carry turns under `input` (an array of items). A bare
	// string `input` has no tool output to compress.
	let input = root.get("input")?.as_array()?;
	let mut w = Walk::default();

	for (item_idx, item) in input.iter().enumerate() {
		let item_path = vec![
			PathItem::Key("input".to_string()),
			PathItem::Index(item_idx),
		];
		match item.get("type").and_then(Value::as_str) {
			// Tool outputs the model reads back. `output` is either a JSON string
			// or a list of content parts ({type, text, ...}).
			Some("function_call_output" | "custom_tool_call_output") => {
				let mut output_path = item_path.clone();
				output_path.push(PathItem::Key("output".to_string()));
				match item.get("output") {
					Some(Value::String(text)) => maybe_push(&mut w, &output_path, text, strategies),
					Some(Value::Array(parts)) => collect_text_parts(&mut w, &output_path, parts, strategies),
					_ => {},
				}
			},
			// Prior message turns: `content` is a string or a list of
			// input_text/output_text parts (each carrying a `text` field).
			Some("message") => {
				let mut content_path = item_path.clone();
				content_path.push(PathItem::Key("content".to_string()));
				match item.get("content") {
					Some(Value::String(text)) => maybe_push(&mut w, &content_path, text, strategies),
					Some(Value::Array(parts)) => collect_text_parts(&mut w, &content_path, parts, strategies),
					_ => {},
				}
			},
			_ => {},
		}
	}

	Some(w)
}

fn collect_text_parts(w: &mut Walk, path: &[PathItem], parts: &[Value], strategies: StrategySet) {
	for (part_idx, part) in parts.iter().enumerate() {
		let mut part_path = path.to_vec();
		part_path.push(PathItem::Index(part_idx));
		collect_key(w, &part_path, part, "text", strategies);
	}
}

fn collect_key(w: &mut Walk, path: &[PathItem], obj: &Value, key: &str, strategies: StrategySet) {
	if let Some(text) = obj.get(key).and_then(Value::as_str) {
		let mut p = path.to_vec();
		p.push(PathItem::Key(key.to_string()));
		maybe_push(w, &p, text, strategies);
	}
}

fn maybe_push(w: &mut Walk, path: &[PathItem], text: &str, strategies: StrategySet) {
	w.walked += 1;
	if text.len() >= dispatch::MIN_BYTES {
		w.eligible += 1;
	}
	if let Some((_strategy, compressed)) = dispatch::compress_with(text, strategies) {
		w.replacements.push((path.to_vec(), compressed));
	}
}

pub fn apply_string_replacements(
	body: &[u8],
	replacements: Vec<(Vec<PathItem>, String)>,
) -> Option<Vec<u8>> {
	if replacements.is_empty() {
		return None;
	}
	let replacements = replacements
		.into_iter()
		.map(|(path, text)| {
			serde_json::to_vec(&text)
				.ok()
				.map(|encoded| Replacement { path, encoded })
		})
		.collect::<Option<Vec<_>>>()?;

	let mut scanner = Scanner {
		body,
		pos: 0,
		targets: &replacements,
		spans: Vec::new(),
	};
	scanner.parse_value(&mut Vec::new())?;
	scanner.skip_ws();
	if scanner.pos != body.len() || scanner.spans.is_empty() {
		return None;
	}

	let mut out = body.to_vec();
	for span in scanner.spans.into_iter().rev() {
		out.splice(span.start..span.end, span.encoded);
	}
	Some(out)
}

struct Scanner<'a> {
	body: &'a [u8],
	pos: usize,
	targets: &'a [Replacement],
	spans: Vec<SpanReplacement>,
}

impl Scanner<'_> {
	fn parse_value(&mut self, path: &mut Vec<PathItem>) -> Option<()> {
		self.skip_ws();
		match *self.body.get(self.pos)? {
			b'{' => self.parse_object(path),
			b'[' => self.parse_array(path),
			b'"' => {
				let (start, end) = self.parse_string_span()?;
				if let Some(target) = self.targets.iter().find(|target| target.path == *path) {
					self.spans.push(SpanReplacement {
						start,
						end,
						encoded: target.encoded.clone(),
					});
				}
				Some(())
			},
			b't' => self.consume_literal(b"true"),
			b'f' => self.consume_literal(b"false"),
			b'n' => self.consume_literal(b"null"),
			b'-' | b'0'..=b'9' => self.consume_number(),
			_ => None,
		}
	}

	fn parse_object(&mut self, path: &mut Vec<PathItem>) -> Option<()> {
		self.pos += 1;
		self.skip_ws();
		if self.eat(b'}') {
			return Some(());
		}
		loop {
			self.skip_ws();
			let (key_start, key_end) = self.parse_string_span()?;
			let key: String = serde_json::from_slice(&self.body[key_start..key_end]).ok()?;
			self.skip_ws();
			if !self.eat(b':') {
				return None;
			}
			path.push(PathItem::Key(key));
			self.parse_value(path)?;
			path.pop();
			self.skip_ws();
			if self.eat(b'}') {
				return Some(());
			}
			if !self.eat(b',') {
				return None;
			}
		}
	}

	fn parse_array(&mut self, path: &mut Vec<PathItem>) -> Option<()> {
		self.pos += 1;
		self.skip_ws();
		if self.eat(b']') {
			return Some(());
		}
		let mut idx = 0;
		loop {
			path.push(PathItem::Index(idx));
			self.parse_value(path)?;
			path.pop();
			idx += 1;
			self.skip_ws();
			if self.eat(b']') {
				return Some(());
			}
			if !self.eat(b',') {
				return None;
			}
		}
	}

	fn parse_string_span(&mut self) -> Option<(usize, usize)> {
		let start = self.pos;
		if !self.eat(b'"') {
			return None;
		}
		while let Some(&b) = self.body.get(self.pos) {
			match b {
				b'"' => {
					self.pos += 1;
					return Some((start, self.pos));
				},
				b'\\' => {
					self.pos += 1;
					self.body.get(self.pos)?;
					self.pos += 1;
				},
				_ => self.pos += 1,
			}
		}
		None
	}

	fn consume_literal(&mut self, lit: &[u8]) -> Option<()> {
		if self.body.get(self.pos..self.pos + lit.len())? == lit {
			self.pos += lit.len();
			Some(())
		} else {
			None
		}
	}

	fn consume_number(&mut self) -> Option<()> {
		let start = self.pos;
		while matches!(
			self.body.get(self.pos),
			Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
		) {
			self.pos += 1;
		}
		(self.pos > start).then_some(())
	}

	fn skip_ws(&mut self) {
		while matches!(self.body.get(self.pos), Some(b' ' | b'\n' | b'\r' | b'\t')) {
			self.pos += 1;
		}
	}

	fn eat(&mut self, b: u8) -> bool {
		if self.body.get(self.pos) == Some(&b) {
			self.pos += 1;
			true
		} else {
			false
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn splices_only_target_string() {
		let body =
			br#"{"model":"x","messages":[{"role":"user","content":"abc"}],"vendor":{"keep":true}}"#;
		let out = apply_string_replacements(
			body,
			vec![(
				vec![
					PathItem::Key("messages".to_string()),
					PathItem::Index(0),
					PathItem::Key("content".to_string()),
				],
				"def".to_string(),
			)],
		)
		.unwrap();
		assert_eq!(
			std::str::from_utf8(&out).unwrap(),
			r#"{"model":"x","messages":[{"role":"user","content":"def"}],"vendor":{"keep":true}}"#
		);
	}
}
