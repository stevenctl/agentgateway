//! Context-edit framework. MVP: gateway-decided, deterministic headroom
//! compression of model-visible text fragments, run eagerly on egress.
//!
//! Full design + the metamem reuse blueprint (fragment/handle addressing, the
//! response interceptor, the decision store, per-format enactment) lives in
//! `.claude/plans/deterministic-compression-and-metamem-seams.md`. This module
//! ships the concrete compression path; the broader seams get code-ified when a
//! metamem fork is built.
//!
//! Scope split with `headroom-core`: we reuse only its **content detection**
//! (`detect_content_type`) and **compressors** (SmartCrusher / Log / Search /
//! Diff). We do **not** use its LiveZone dispatcher, freeze-floor / cache
//! tracking, CCR store, or marker injection — that orchestration is ours (see
//! [`anthropic`]). Deterministic compression is a pure function of the request,
//! so this path keeps **no state**.

pub mod anthropic;
pub mod completions;
pub mod config;
pub mod dispatch;
pub mod fragments;
pub mod responses;
pub mod simulate;

use super::{AIProvider, InputFormat};
use dispatch::StrategySet;

/// Resolved, runtime-ready context-edit policy attached to an
/// [`super::policy::Policy`]. Built once at config translation, shared read-only
/// across requests behind an `Arc`. (Replaces the old CCR-store-based
/// `CompressionPolicy` + `ResolvedCcr`.)
#[derive(Debug, Clone)]
pub struct ContextEditPolicy {
	/// Enable deterministic headroom compression.
	pub headroom: bool,
	/// Enable deterministic GCF encoding for JSON text fragments.
	pub gcf: bool,
	/// Analyze-only: run the compressor + cache-impact analysis on each request
	/// and log it, but forward the original bytes unchanged. Lets a single
	/// baseline run answer "would compression fire" and "would it bust the cache"
	/// without changing behavior or cost. See [`simulate`].
	pub simulate: bool,
}

impl ContextEditPolicy {
	/// ❷ egress entry — called from `process_request` on the final serialized
	/// provider bytes (the cache-alignment boundary the upstream caches against).
	///
	/// Dispatch is by provider wire shape: Anthropic-shaped bodies go through
	/// [`anthropic`]; OpenAI-family bodies are either chat-completions
	/// ([`completions`]) or Responses ([`responses`]) — `format` picks which, with
	/// a fall-back to the other shape since the egress wire shape depends on both
	/// the input format and the provider's conversion. Fail-open everywhere: a
	/// parse error or no-op result forwards the original `body` unchanged, so a
	/// body that doesn't match the expected shape (e.g. embeddings) is simply
	/// passed through.
	///
	/// Deferred: Gemini/Vertex/Bedrock native shapes (no-op for now).
	pub fn maybe_compact(
		&self,
		provider: &AIProvider,
		format: InputFormat,
		_model: &str,
		body: Vec<u8>,
	) -> Vec<u8> {
		let strategies = StrategySet {
			headroom: self.headroom,
			gcf: self.gcf,
		};
		// Analyze-only pass (Anthropic shape only for now): log what compression
		// would do — fired fragments, token savings, and prompt-cache invalidation
		// — without rewriting the request. Independent of `headroom`.
		if self.simulate {
			if let AIProvider::Anthropic(_) = provider {
				if let Some(a) = simulate::analyze(&body, strategies) {
					tracing::info!(
						target: "agentgateway::llm::ctxedit",
						messages = a.total_messages,
						eligible = a.eligible,
						fired = a.fired,
						saved_bytes = a.saved_bytes,
						saved_tokens = a.saved_tokens,
						first_changed_msg = a.first_changed_msg.map(|v| v as i64).unwrap_or(-1),
						breakpoints = a.n_breakpoints,
						busted_breakpoints = a.busted_breakpoints,
						cached_tokens_at_risk = a.cached_tokens_at_risk,
						"ctxedit simulate"
					);
				}
			}
			return body;
		}

		if !strategies.any() {
			return body;
		}
		// Walk the body to find compressible fragments. `*_replacements` returns
		// `Some(Walk)` whenever the body parses and matches the shape — even with
		// nothing to compress — so we get walk accounting (visited/eligible) for
		// the matched shape, and the OpenAI-family fallback picks the walker whose
		// shape actually matched.
		//
		// OpenAI + OpenAI-compatible: the egress body is chat-completions
		// (`messages[]`) for Completions/Messages input, or Responses (`input[]`,
		// e.g. Codex) when Responses input is passed through. Pick by `format`,
		// falling back to the other shape so an unusual format/conversion pairing
		// (e.g. a Custom backend translating Responses→Completions) still
		// compresses. The shapes are disjoint, so the fallback is safe. `Custom`
		// covers openai-compatible upstreams; a body that's neither shape fails
		// both parses → no walker → original bytes forwarded.
		let walk_responses =
			|| fragments::responses_replacements(&body, strategies).map(|w| ("responses", w));
		let walk_completions =
			|| fragments::completions_replacements(&body, strategies).map(|w| ("completions", w));
		let walked = match provider {
			AIProvider::Anthropic(_) => {
				fragments::anthropic_replacements(&body, strategies).map(|w| ("anthropic", w))
			},
			AIProvider::OpenAI(_)
			| AIProvider::Azure(_)
			| AIProvider::Copilot(_)
			| AIProvider::Custom(_) => {
				if format == InputFormat::Responses {
					walk_responses().or_else(walk_completions)
				} else {
					walk_completions().or_else(walk_responses)
				}
			},
			// Deferred: native Gemini/Vertex/Bedrock shapes. Each needs its own
			// per-format fragment walk.
			AIProvider::Gemini(_) | AIProvider::Vertex(_) | AIProvider::Bedrock(_) => None,
		};

		let Some((walker, w)) = walked else {
			// No walker matched: unsupported provider, or a body that's neither
			// chat-completions nor Responses (e.g. embeddings). Forward unchanged.
			tracing::debug!(
				target: "agentgateway::llm::ctxedit",
				provider = %provider.provider(),
				?format,
				"ctxedit walk: no matching walker (body shape unsupported)"
			);
			return body;
		};

		// One line per request — confirms the walker ran and reports eligibility
		// even when nothing compressed, so a quiet run is provably
		// "walked, nothing compressible" rather than "walker never reached".
		// Enable with RUST_LOG=agentgateway::llm::ctxedit=debug.
		tracing::debug!(
			target: "agentgateway::llm::ctxedit",
			walker,
			walked = w.walked,
			eligible = w.eligible,
			compressed = w.replacements.len(),
			"ctxedit walk"
		);

		fragments::apply_string_replacements(&body, w.replacements).unwrap_or(body)
	}
}
