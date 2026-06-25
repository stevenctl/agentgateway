use serde_json::Value;

use super::methods;

/// What a leaf visit decided. Merges up the tree; `Rejected` short-circuits.
#[derive(Clone, Copy, Eq, PartialEq)]
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

	fn then(self, next: impl FnOnce() -> Self) -> Self {
		if self == Self::Rejected {
			self // already rejected, short-circuit
		} else {
			self.merge(next())
		}
	}
}

/// A per-leaf visitor: inspect (and possibly rewrite) one text in place.
pub(crate) type Leaf<'a> = &'a mut dyn FnMut(&mut String) -> VisitOutcome;

/// A method's traversal: walk the inspectable text of a decoded body, driving each
/// leaf through the caller's `Leaf`. Captures nothing, so it's a plain `fn`.
pub(crate) type Visit = fn(&mut Value, Leaf<'_>) -> VisitOutcome;

pub(crate) fn request_visit(method: &str) -> Option<Visit> {
	let visit: Visit = match method {
		methods::TOOLS_CALL | methods::PROMPTS_GET => |v, leaf| walk_at(v, "arguments", leaf),
		methods::RESOURCES_READ => |v, leaf| field(v, "uri", leaf),
		_ => return None,
	};
	Some(visit)
}

pub(crate) fn response_visit(method: &str) -> Option<Visit> {
	let visit: Visit = match method {
		methods::TOOLS_LIST => |v, leaf| drop_matching(v, "tools", leaf),
		methods::PROMPTS_LIST => |v, leaf| drop_matching(v, "prompts", leaf),
		methods::RESOURCES_LIST => |v, leaf| drop_matching(v, "resources", leaf),
		methods::RESOURCES_TEMPLATES_LIST => |v, leaf| drop_matching(v, "resourceTemplates", leaf),
		methods::TOOLS_CALL => |v, leaf| {
			array(v, "content", |c| content_block(c, &mut *leaf))
				.then(|| walk_at(v, "structuredContent", leaf))
		},
		methods::RESOURCES_READ => |v, leaf| array(v, "contents", |c| field(c, "text", &mut *leaf)),
		methods::PROMPTS_GET => |v, leaf| {
			field(v, "description", &mut *leaf).then(|| {
				array(v, "messages", |msg| match msg.get_mut("content") {
					Some(content) => content_block(content, &mut *leaf),
					None => VisitOutcome::Pass,
				})
			})
		},
		_ => return None,
	};
	Some(visit)
}

fn each<T>(
	items: impl IntoIterator<Item = T>,
	mut f: impl FnMut(T) -> VisitOutcome,
) -> VisitOutcome {
	let mut outcome = VisitOutcome::Pass;
	for item in items {
		outcome = outcome.merge(f(item));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn walk(value: &mut Value, leaf: Leaf) -> VisitOutcome {
	match value {
		// TODO we need to look at non-string fields too probably
		Value::String(text) => leaf(text),
		Value::Array(values) => each(values, |v| walk(v, &mut *leaf)),
		Value::Object(values) => each(values.values_mut(), |v| walk(v, &mut *leaf)),
		_ => VisitOutcome::Pass,
	}
}

// look at a specific field by name
fn field(value: &mut Value, key: &str, leaf: Leaf) -> VisitOutcome {
	match value.get_mut(key) {
		Some(Value::String(text)) => leaf(text),
		_ => VisitOutcome::Pass,
	}
}

// look at the entirety of the object at the given key, recursively
fn walk_at(value: &mut Value, key: &str, leaf: Leaf) -> VisitOutcome {
	match value.get_mut(key) {
		Some(child) => walk(child, leaf),
		None => VisitOutcome::Pass,
	}
}

// look at each element of the array at the given key,
// used when a specific shape is expected for each element
fn array(value: &mut Value, key: &str, f: impl FnMut(&mut Value) -> VisitOutcome) -> VisitOutcome {
	match value.get_mut(key).and_then(Value::as_array_mut) {
		Some(items) => each(items, f),
		None => VisitOutcome::Pass,
	}
}

fn content_block(block: &mut Value, leaf: Leaf) -> VisitOutcome {
	match block.get("type").and_then(Value::as_str) {
		Some("text") => field(block, "text", leaf),
		Some("resource") => match block.get_mut("resource") {
			Some(resource) => {
				field(resource, "text", &mut *leaf).then(|| match resource.get_mut("resource") {
					Some(contents) => field(contents, "text", leaf),
					None => VisitOutcome::Pass,
				})
			},
			None => VisitOutcome::Pass,
		},
		Some("resource_link") => each(["name", "title", "description"], |key| {
			field(block, key, &mut *leaf)
		}),
		_ => VisitOutcome::Pass,
	}
}

// drop_matching removes entries rather than mutating masking.
// this is a conservative way to avoid mutating things like identifiers and schema that
// the client/agent would rely on for subsequent calls, for example:
// tools/list -> modify get_ssn to get_<masked> -> tools/call get_<masked> -> error because tool not found
fn drop_matching(value: &mut Value, list_key: &str, leaf: Leaf) -> VisitOutcome {
	let Some(entries) = value.get_mut(list_key).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};

	let mut outcome = VisitOutcome::Pass;
	entries.retain_mut(|entry| match walk(entry, &mut *leaf) {
		VisitOutcome::Pass => true,
		VisitOutcome::Mutated => {
			outcome = outcome.merge(VisitOutcome::Mutated);
			false
		},
		VisitOutcome::Rejected => {
			outcome = VisitOutcome::Rejected;
			false
		},
	});
	outcome
}
