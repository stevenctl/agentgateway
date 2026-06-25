//! Per-fragment compression: the whole of our `headroom-core` dependency.
//!
//! `detect_content_type(text)` picks a [`ContentType`]; we dispatch to the
//! matching compressor (SmartCrusher / Log / Search / Diff). This mirrors the
//! routing headroom's LiveZone did internally — but the routing logic is *ours*
//! now, so it lives here and not behind their cache-aware dispatcher.

use std::sync::OnceLock;

use headroom_core::transforms::smart_crusher::{SmartCrusher, SmartCrusherConfig};
use headroom_core::transforms::{
	ContentType, DiffCompressor, DiffCompressorConfig, LogCompressor, LogCompressorConfig,
	SearchCompressor, SearchCompressorConfig, detect_content_type,
};
use serde_json::Value;

/// Below this many bytes we don't bother — per-call overhead dwarfs the savings,
/// and tiny inputs rarely compress. Matches headroom's per-type thresholds (512).
pub const MIN_BYTES: usize = 512;
/// The dispatcher does not yet plumb the user's last prompt as a relevance query.
///
/// ⚠️ CACHE-SAFETY INVARIANT: keep this constant (and `DEFAULT_BIAS`). Compression
/// must stay a pure function of the fragment's *content* only — no query, bias, or
/// any per-turn/positional input. That determinism is what makes us prompt-cache
/// safe: the client resends the same uncompressed fragment B every turn, we
/// compress B → B' identically, and the upstream's cached (compressed) prefix
/// stays byte-stable → steady-state cache hit, no ongoing busting. The moment a
/// real relevance query or per-turn bias is wired in, the same fragment would
/// compress differently each turn → the cached prefix changes every turn →
/// genuine, recurring cache invalidation. If you plumb a query/bias here, it MUST
/// be re-evaluated for cache safety (e.g. freeze the query within a session, or
/// only vary compression in the uncached tail past the last cache breakpoint).
const EMPTY_QUERY: &str = "";
/// "No relevance bias" — mirrors the OSS default. See `EMPTY_QUERY` cache-safety note.
const DEFAULT_BIAS: f64 = 0.0;

#[derive(Debug, Clone, Copy)]
pub struct StrategySet {
	pub headroom: bool,
	pub gcf: bool,
}

impl StrategySet {
	pub const fn headroom_only() -> Self {
		Self {
			headroom: true,
			gcf: false,
		}
	}

	pub const fn any(self) -> bool {
		self.headroom || self.gcf
	}
}

fn smart_crusher() -> &'static SmartCrusher {
	static I: OnceLock<SmartCrusher> = OnceLock::new();
	I.get_or_init(|| SmartCrusher::new(SmartCrusherConfig::default()))
}
fn log_compressor() -> &'static LogCompressor {
	static I: OnceLock<LogCompressor> = OnceLock::new();
	I.get_or_init(|| LogCompressor::new(LogCompressorConfig::default()))
}
fn search_compressor() -> &'static SearchCompressor {
	static I: OnceLock<SearchCompressor> = OnceLock::new();
	I.get_or_init(|| SearchCompressor::new(SearchCompressorConfig::default()))
}
fn diff_compressor() -> &'static DiffCompressor {
	static I: OnceLock<DiffCompressor> = OnceLock::new();
	I.get_or_init(|| DiffCompressor::new(DiffCompressorConfig::default()))
}

/// Detect + compress one fragment's content. Returns `(strategy, compressed)`,
/// or `None` when the content is left unchanged: below threshold, an unsupported
/// content type, or the compressor did not actually shrink it.
///
/// The "actually smaller" gate is byte-based here (MVP). headroom uses a
/// tokenizer-validated gate; we can swap in agentgateway's tiktoken BPE later so
/// the check is in the currency the upstream bills.
pub fn compress(content: &str) -> Option<(&'static str, String)> {
	compress_with(content, StrategySet::headroom_only())
}

pub fn compress_with(content: &str, strategies: StrategySet) -> Option<(&'static str, String)> {
	if content.len() < MIN_BYTES {
		return None;
	}

	let mut best: Option<(&'static str, String)> = None;

	if strategies.gcf {
		if let Some(out) = compress_gcf(content) {
			best = Some(("gcf_json", out));
		}
	}

	if strategies.headroom {
		if let Some((strategy, out)) = compress_headroom(content) {
			if best
				.as_ref()
				.is_none_or(|(_best_strategy, best_out)| out.len() < best_out.len())
			{
				best = Some((strategy, out));
			}
		}
	}

	let (strategy, out) = best?;
	// Observability for the compression experiment: one line per fragment that
	// actually shrank. Enable with RUST_LOG=agentgateway::llm::ctxedit=debug.
	tracing::debug!(
		strategy,
		before = content.len(),
		after = out.len(),
		saved_pct = 100.0 * (1.0 - (out.len() as f64 / content.len() as f64)),
		"ctxedit compressed tool result"
	);
	Some((strategy, out))
}

fn compress_gcf(content: &str) -> Option<String> {
	let value: Value = serde_json::from_str(content).ok()?;
	let out = gcf::encode_generic(&value);
	(out.len() < content.len()).then_some(out)
}

fn compress_headroom(content: &str) -> Option<(&'static str, String)> {
	let (strategy, out) = match detect_content_type(content).content_type {
		ContentType::JsonArray => {
			let r = smart_crusher().crush(content, EMPTY_QUERY, DEFAULT_BIAS);
			if !r.was_modified {
				return None;
			}
			("smart_crusher", r.compressed)
		},
		ContentType::BuildOutput => {
			let (r, _stats) = log_compressor().compress(content, DEFAULT_BIAS);
			("log_compressor", r.compressed)
		},
		ContentType::SearchResults => {
			let (r, _stats) = search_compressor().compress(content, EMPTY_QUERY, DEFAULT_BIAS);
			("search_compressor", r.compressed)
		},
		ContentType::GitDiff => {
			let r = diff_compressor().compress(content, EMPTY_QUERY);
			("diff_compressor", r.compressed)
		},
		// Intentionally never compressed. Source code and plain prose are
		// exact-fidelity content — the model depends on them verbatim, so a lossy
		// transform is not acceptable here regardless of savings. (This is a
		// deliberate scope decision, not a missing port.) HTML simply has no
		// compressor. Only structured/semi-structured types above are eligible.
		ContentType::SourceCode | ContentType::PlainText | ContentType::Html => return None,
	};

	(out.len() < content.len()).then_some((strategy, out))
}
