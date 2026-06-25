//! Analyze-only "simulation" of headroom compression on an Anthropic
//! `/v1/messages` request. Runs the *real* compressor ([`super::dispatch`]) over
//! eligible tool results but **discards** the rewrite — the caller forwards the
//! original bytes. Emits two signals the compression experiment cares about:
//!
//!   #1 would-it-fire: per eligible tool_result, did `dispatch::compress` shrink
//!      it, and by how many bytes/tokens.
//!   #2 cache impact: the index of the first message whose bytes would change,
//!      and how many `cache_control`-cached tokens sit at/after that point — i.e.
//!      what compression would invalidate in Anthropic's prompt cache.
//!
//! Token counts are a cl100k estimate (Anthropic bills its own tokenizer); they
//! are for relative deltas, not exact billing — cross-check magnitudes against
//! the real `cache_read`/`cache_creation` in the gateway access log.

use std::sync::OnceLock;

use tiktoken_rs::CoreBPE;

use crate::llm::types::messages::typed::{
	ContentBlock, Message, Request, SystemPrompt, ToolResultContent,
};

use super::dispatch::{self, StrategySet};

fn bpe() -> &'static CoreBPE {
	static I: OnceLock<CoreBPE> = OnceLock::new();
	I.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k tokenizer"))
}

fn toks(s: &str) -> usize {
	bpe().encode_with_special_tokens(s).len()
}

/// Tokens of a whole message as it serializes into the prompt prefix (uniform
/// proxy for cache-region sizing).
fn msg_tokens(m: &Message) -> usize {
	serde_json::to_string(m).map(|s| toks(&s)).unwrap_or(0)
}

fn block_has_cache(b: &ContentBlock) -> bool {
	matches!(
		b,
		ContentBlock::Text(t) if t.cache_control.is_some())
		|| matches!(b, ContentBlock::Image(i) if i.cache_control.is_some())
		|| matches!(b, ContentBlock::Document(d) if d.cache_control.is_some())
		|| matches!(b, ContentBlock::SearchResult(s) if s.cache_control.is_some())
		|| matches!(
			b,
			ContentBlock::ToolUse {
				cache_control: Some(_),
				..
			}
		) || matches!(
		b,
		ContentBlock::ToolResult {
			cache_control: Some(_),
			..
		}
	) || matches!(
		b,
		ContentBlock::ServerToolUse {
			cache_control: Some(_),
			..
		}
	) || matches!(
		b,
		ContentBlock::WebSearchToolResult {
			cache_control: Some(_),
			..
		}
	)
}

fn msg_has_cache(m: &Message) -> bool {
	m.content.iter().any(block_has_cache)
}

fn system_has_cache(s: &Option<SystemPrompt>) -> bool {
	matches!(s, Some(SystemPrompt::Blocks(blocks))
	if blocks.iter().any(|b| {
		let crate::llm::types::messages::typed::SystemContentBlock::Text { cache_control, .. } = b;
		cache_control.is_some()
	}))
}

/// Result of one request's simulation. Rendered into a single structured log line.
#[derive(Default, Debug)]
pub struct Analysis {
	pub total_messages: usize,
	pub eligible: usize,
	pub fired: usize,
	pub saved_bytes: i64,
	pub saved_tokens: i64,
	pub first_changed_msg: Option<usize>,
	pub n_breakpoints: usize,
	/// Breakpoints at/after the first changed message — these caches bust.
	pub busted_breakpoints: usize,
	/// Tokens in [first_changed ..= last_breakpoint] — the cached span compression
	/// would invalidate (forcing re-creation upstream).
	pub cached_tokens_at_risk: usize,
}

/// Simulate compression on an Anthropic body. `None` if it doesn't parse (the
/// caller still forwards the original bytes).
pub fn analyze(body: &[u8], strategies: StrategySet) -> Option<Analysis> {
	let req: Request = serde_json::from_slice(body).ok()?;
	let total = req.messages.len();
	let mut a = Analysis {
		total_messages: total,
		..Default::default()
	};

	// #1 — run the real compressor over every eligible (string) tool result,
	// matching `anthropic::compress`: compress from first sight, latest included.
	for (idx, msg) in req.messages.iter().enumerate() {
		for block in &msg.content {
			let ContentBlock::ToolResult {
				content: ToolResultContent::Text(text),
				..
			} = block
			else {
				continue;
			};
			a.eligible += 1;
			if let Some((_strategy, out)) = dispatch::compress_with(text, strategies) {
				a.fired += 1;
				a.saved_bytes += text.len() as i64 - out.len() as i64;
				a.saved_tokens += toks(text) as i64 - toks(&out) as i64;
				a.first_changed_msg = Some(a.first_changed_msg.map_or(idx, |p| p.min(idx)));
			}
		}
	}

	// #2 — cache breakpoints and the span at risk if compression changed bytes.
	let breakpoints: Vec<usize> = req
		.messages
		.iter()
		.enumerate()
		.filter(|(_, m)| msg_has_cache(m))
		.map(|(i, _)| i)
		.collect();
	a.n_breakpoints = breakpoints.len() + usize::from(system_has_cache(&req.system));

	if let Some(first) = a.first_changed_msg {
		a.busted_breakpoints = breakpoints.iter().filter(|&&b| b >= first).count();
		if let Some(&last_bp) = breakpoints.iter().filter(|&&b| b >= first).max() {
			a.cached_tokens_at_risk = req.messages[first..=last_bp].iter().map(msg_tokens).sum();
		}
	}

	Some(a)
}
