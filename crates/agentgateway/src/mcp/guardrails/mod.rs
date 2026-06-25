//! External MCP policy hooks (mcpGuardrails).
//!
//! Single-target methods (`tools/call`, ...) fire server-facing in the upstream's
//! native namespace — processors see unmuxed names (`echo`, not `serverA_echo`) and the
//! lone backend name in `service_names`. Fanout methods (`*/list`, ...) run the hook
//! once for the whole client call (request hook before fanout, response hook on the
//! merged result). Names there match the client-facing view, which tracks the
//! multiplexing config rather than the method: muxed names when multiplexing, a single
//! backend's unmuxed names when there is just one (the usual single-backend case).
//! `service_names` lists every fanned-out backend either way.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;

use crate::mcp::upstream::IncomingRequestContext;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{BackendTrafficPolicy, SimpleBackendReference};
use crate::*;

/// Per-request bag of values that `mcpGuardrails` request-phase processors attach via
/// `McpRequestResult.metadata`. Merged into the request extensions and exposed
/// to CEL as `mcpGuardrails.<key>` for backend request filters (e.g. `transformation`).
/// Multiple processors merge into the same map; later writes win on key collisions.
#[apply(schema!)]
#[derive(Default, ::cel::DynamicType)]
pub struct McpGuardrailsDynamicMetadata(serde_json::Map<String, serde_json::Value>);

impl McpGuardrailsDynamicMetadata {
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

mod client;
mod llm;
pub mod methods;
mod payload;
pub mod phase;
mod regex;

pub use llm::{
	AzureContentSafetyProcessor, BedrockGuardrailsProcessor, GoogleModelArmorProcessor,
	WebhookProcessor,
};
pub use phase::Phase;
pub use regex::RegexProcessor;

#[derive(Debug)]
pub enum Outcome<T> {
	Pass,
	Mutated(T),
	Reject(rmcp::model::ErrorData),
}

const DEFAULT_REJECTION: &str = "MCP call blocked by guardrail policy";

/// JSON-RPC client facing error config for when a processor rejects a request or response.
#[apply(schema!)]
#[derive(Default)]
pub struct McpRejection {
	/// JSON-RPC error message. Defaults to a generic policy-violation message.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,
}

impl McpRejection {
	/// Render the JSON-RPC error returned when a rule matches under `action: reject`.
	fn to_error(&self) -> rmcp::model::ErrorData {
		let message = self
			.message
			.clone()
			.unwrap_or_else(|| DEFAULT_REJECTION.to_string());
		rmcp::model::ErrorData::new(client::PERMISSION_DENIED, message, None)
	}
}

pub mod wire {
	pub use protos::ext_mcp::*;
}

#[apply(schema!)]
#[derive(Default)]
pub struct McpGuardrails {
	/// Ordered list of policy processors applied to matched methods; the first
	/// to reject a request short-circuits the chain. Processors may run on the
	/// request or response side, or both; see `Processor.methods`.
	pub processors: Vec<Processor>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Processor {
	/// Allowlist: only methods listed here run through this processor, at the
	/// configured phase. Keys may be exact (`tools/call`), prefix (`tools/*`),
	/// or suffix (`*/list`) wildcards, or `*` for all methods. Methods matching
	/// no key bypass this processor; see [`phase::resolve`] for match precedence.
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub methods: HashMap<String, Phase>,
	#[serde(flatten)]
	pub kind: ProcessorKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProcessorKind {
	/// Call a remote ExtMCP service to apply rules. See [`Remote`] for config.
	Remote(Remote),
	/// Apply regex/PII rules in-process.
	Regex(RegexProcessor),
	/// Call a webhook over the inspectable text of MCP bodies.
	Webhook(WebhookProcessor),
	/// Apply AWS Bedrock Guardrails over the inspectable text of MCP bodies.
	BedrockGuardrails(BedrockGuardrailsProcessor),
	/// Apply Google Model Armor over the inspectable text of MCP bodies.
	GoogleModelArmor(GoogleModelArmorProcessor),
	/// Apply Azure Content Safety over the inspectable text of MCP bodies.
	AzureContentSafety(AzureContentSafetyProcessor),
}

impl McpGuardrails {
	/// Whether any processor runs the request side for `method`.
	pub fn runs_request(&self, method: &str) -> bool {
		self.processors.iter().any(|d| d.runs_request(method))
	}

	/// Whether any processor runs the response side for `method`.
	pub fn runs_response(&self, method: &str) -> bool {
		self.processors.iter().any(|d| d.runs_response(method))
	}

	/// Config warnings to surface at load time (xds diagnostics or logs).
	pub fn load_warnings(&self) -> Vec<String> {
		let mut out = Vec::new();
		for m in methods::REQUEST_PHASE_UNSUPPORTED {
			if self.runs_request(m) {
				out.push(format!(
					"mcpGuardrails: methods match {m:?} with a request phase, but only the response phase runs for this method"
				));
			}
		}
		let mut bad_patterns: Vec<_> = self
			.processors
			.iter()
			.flat_map(|d| d.methods.keys())
			.filter(|p| !phase::pattern_is_matchable(p))
			.map(|p| {
				format!(
					"mcpGuardrails: methods key {p:?} can never match; use an exact method, 'prefix/*', '*/suffix', or '*'"
				)
			})
			.collect();
		bad_patterns.sort();
		out.append(&mut bad_patterns);
		out
	}
}

// Retries and load balancing come from the backend referenced by `target`;
// TLS/auth may also be set inline via `policies`.
#[apply(schema!)]
pub struct Remote {
	/// Reference to the external MCP policy service backend.
	#[serde(flatten)]
	pub target: Arc<SimpleBackendReference>,
	/// Policies to connect to the backend.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[serde(deserialize_with = "crate::types::local::de_from_local_backend_policy")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
	/// Behavior when the processor is unavailable or returns an error.
	#[serde(default)]
	pub failure_mode: FailureMode,
	/// CEL expressions evaluated per request and sent to the processor as metadata.
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub metadata: HashMap<String, Arc<cel::Expression>>,
	/// Which incoming request headers are forwarded to the policy server.
	#[serde(default, skip_serializing_if = "HeaderFilter::is_default")]
	pub request_headers: HeaderFilter,
}

/// Allow/deny filter over request headers, mirroring ext_authz: empty `allowed`
/// forwards every header plus all pseudo-headers (`:authority`, `:method`, ...);
/// a non-empty `allowed` forwards only the listed names. `disallowed` always
/// wins. Header names match case-insensitively; pseudo-headers match exactly.
#[apply(schema!)]
#[derive(Default)]
pub struct HeaderFilter {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allowed: Vec<crate::http::HeaderOrPseudo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub disallowed: Vec<crate::http::HeaderOrPseudo>,
}

impl HeaderFilter {
	fn is_default(&self) -> bool {
		self.allowed.is_empty() && self.disallowed.is_empty()
	}
	/// Whether a header (or pseudo-header) should be sent to the policy server.
	pub fn allows(&self, name: &crate::http::HeaderOrPseudo) -> bool {
		if self.disallowed.iter().any(|n| n == name) {
			return false;
		}
		self.allowed.is_empty() || self.allowed.iter().any(|n| n == name)
	}
}

// Behavior when a processor errors or returns an unhandleable response.
#[apply(schema_enum!)]
#[derive(Default)]
pub enum FailureMode {
	#[default]
	FailClosed,
	FailOpen,
}

/// `params` is `None` for methods with no per-request body (e.g. `*/list`);
/// any `Mutated` outcome there is logged and discarded.
pub struct CallRequestCtx<'a> {
	pub backends: &'a [String],
	pub method: &'a str,
	pub params: Option<Bytes>,
}

impl Processor {
	fn runs_request(&self, method: &str) -> bool {
		phase::resolve(method, &self.methods).runs_request()
	}

	fn runs_response(&self, method: &str) -> bool {
		phase::resolve(method, &self.methods).runs_response()
	}

	async fn call_request<P: serde::de::DeserializeOwned>(
		&self,
		ctx: &mut CallRequestCtx<'_>,
		req_ctx: &mut IncomingRequestContext,
		client: &PolicyClient,
	) -> Outcome<P> {
		match &self.kind {
			ProcessorKind::Remote(remote) => {
				client::check_request::<P>(
					remote,
					ctx.method,
					ctx.backends,
					ctx.params.as_mut(),
					req_ctx,
					client,
				)
				.await
			},
			ProcessorKind::Regex(rp) => {
				regex::run_request::<P>(rp, ctx.method, ctx.params.as_mut()).await
			},
			ProcessorKind::Webhook(p) => {
				p.run_request::<P>(
					ctx.method,
					ctx.params.as_mut(),
					req_ctx.headers(),
					client,
					req_ctx.claims(),
				)
				.await
			},
			ProcessorKind::BedrockGuardrails(p) => {
				p.run_request::<P>(
					ctx.method,
					ctx.params.as_mut(),
					req_ctx.headers(),
					client,
					req_ctx.claims(),
				)
				.await
			},
			ProcessorKind::GoogleModelArmor(p) => {
				p.run_request::<P>(
					ctx.method,
					ctx.params.as_mut(),
					req_ctx.headers(),
					client,
					req_ctx.claims(),
				)
				.await
			},
			ProcessorKind::AzureContentSafety(p) => {
				p.run_request::<P>(
					ctx.method,
					ctx.params.as_mut(),
					req_ctx.headers(),
					client,
					req_ctx.claims(),
				)
				.await
			},
		}
	}

	async fn response(
		&self,
		method: &str,
		backends: &[String],
		body: &mut Bytes,
		req_ctx: &IncomingRequestContext,
		client: &PolicyClient,
	) -> Outcome<rmcp::model::ServerResult> {
		match &self.kind {
			ProcessorKind::Remote(remote) => {
				client::check_response(remote, method, backends, body, req_ctx, client).await
			},
			ProcessorKind::Regex(rp) => regex::run_response(rp, method, body).await,
			ProcessorKind::Webhook(p) => {
				p.run_response(method, body, req_ctx.headers(), client).await
			},
			ProcessorKind::BedrockGuardrails(p) => {
				p.run_response(method, body, req_ctx.headers(), client).await
			},
			ProcessorKind::GoogleModelArmor(p) => {
				p.run_response(method, body, req_ctx.headers(), client).await
			},
			ProcessorKind::AzureContentSafety(p) => {
				p.run_response(method, body, req_ctx.headers(), client).await
			},
		}
	}
}

/// Processors fire in order; first `Reject` short-circuits leaving `ctx` in whatever
/// partially-mutated state earlier processors produced. When `ctx.params` is `None`
/// (e.g. `*/list`) mutations are discarded — list filtering belongs in the response phase.
pub async fn run_call_request<P: serde::de::DeserializeOwned>(
	ext: &McpGuardrails,
	ctx: &mut CallRequestCtx<'_>,
	req_ctx: &mut IncomingRequestContext,
	client: &PolicyClient,
) -> Outcome<P> {
	let mut composed = Outcome::Pass;
	for processor in &ext.processors {
		if !processor.runs_request(ctx.method) {
			continue;
		}
		match processor.call_request::<P>(ctx, req_ctx, client).await {
			Outcome::Pass => {},
			Outcome::Mutated(p) => composed = Outcome::Mutated(p),
			Outcome::Reject(e) => return Outcome::Reject(e),
		}
	}
	composed
}

/// Processors fire in order; first `Reject` short-circuits.
pub async fn run_response(
	ext: &McpGuardrails,
	method: &str,
	backends: &[String],
	mut body: Bytes,
	req_ctx: &IncomingRequestContext,
	client: &PolicyClient,
) -> Outcome<rmcp::model::ServerResult> {
	let mut composed = Outcome::Pass;
	for processor in &ext.processors {
		if !processor.runs_response(method) {
			continue;
		}
		match processor
			.response(method, backends, &mut body, req_ctx, client)
			.await
		{
			Outcome::Pass => {},
			Outcome::Mutated(r) => composed = Outcome::Mutated(r),
			Outcome::Reject(e) => return Outcome::Reject(e),
		}
	}
	composed
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deser_local_config() {
		let cfg = r#"
processors:
  - kind: remote
    methods: { "tools/call": request, "*/list": response }
    host: 127.0.0.1:9999
    policies:
      backendTLS: {}
    failureMode: failOpen
    requestHeaders:
      allowed: [x-tenant]
      disallowed: [":authority"]
  - kind: remote
    methods: { "tools/call": full }
    backend: my-backend
  - kind: regex
    methods: { "tools/call": full, "*/list": response }
    action: mask
    rules:
      - builtin: ssn
      - pattern: "AKIA[0-9A-Z]{16}"
    rejection:
      message: blocked
"#;
		let ext: McpGuardrails = serde_yaml::from_str(cfg).expect("deser McpGuardrails");
		assert_eq!(ext.processors.len(), 3);

		let d0 = &ext.processors[0];
		assert_eq!(d0.methods.get("tools/call"), Some(&Phase::Request));
		assert_eq!(d0.methods.get("*/list"), Some(&Phase::Response));
		let ProcessorKind::Remote(r0) = &d0.kind else {
			panic!("expected remote processor");
		};
		assert!(matches!(
			r0.target.as_ref(),
			SimpleBackendReference::InlineBackend(_)
		));
		assert_eq!(r0.failure_mode, FailureMode::FailOpen);
		assert_eq!(r0.policies.len(), 1, "backendTLS should translate");
		assert_eq!(r0.request_headers.allowed.len(), 1);
		assert!(
			r0.request_headers
				.disallowed
				.contains(&crate::http::HeaderOrPseudo::Authority)
		);

		let ProcessorKind::Remote(r1) = &ext.processors[1].kind else {
			panic!("expected remote processor");
		};
		assert!(matches!(
			r1.target.as_ref(),
			SimpleBackendReference::Backend(_)
		));
		assert_eq!(r1.failure_mode, FailureMode::FailClosed);

		let ProcessorKind::Regex(r2) = &ext.processors[2].kind else {
			panic!("expected regex processor");
		};
		assert_eq!(r2.rules.rules.len(), 2);
		assert_eq!(r2.rejection.message.as_deref(), Some("blocked"));
	}

	fn ext_with_methods(pairs: &[(&str, Phase)]) -> McpGuardrails {
		McpGuardrails {
			processors: vec![Processor {
				methods: pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
				kind: ProcessorKind::Remote(Remote {
					target: Arc::new(SimpleBackendReference::Backend("b".into())),
					policies: Vec::new(),
					failure_mode: FailureMode::default(),
					metadata: HashMap::new(),
					request_headers: HeaderFilter::default(),
				}),
			}],
		}
	}

	#[test]
	fn warns_on_request_phase_for_unsupported_methods() {
		// A catchall request phase matches subscribe/unsubscribe/complete, none of
		// which run the request hook.
		let warnings = ext_with_methods(&[("*", Phase::Full)]).load_warnings();
		assert_eq!(warnings.len(), 3, "{warnings:?}");
		assert!(warnings[0].contains("resources/subscribe"));

		// Response-only and supported-method configs are clean.
		assert!(
			ext_with_methods(&[("*", Phase::Response), ("tools/call", Phase::Full)])
				.load_warnings()
				.is_empty()
		);
	}

	#[test]
	fn warns_on_unmatchable_method_patterns() {
		let warnings = ext_with_methods(&[
			("a*b", Phase::Response),
			("**", Phase::Response),
			("", Phase::Response),
			("tools/*", Phase::Response),
			("*/list", Phase::Response),
		])
		.load_warnings();
		assert_eq!(warnings.len(), 3, "{warnings:?}");
		assert!(warnings.iter().all(|w| w.contains("can never match")));
	}
}
