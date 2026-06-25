//! Config-facing types for the context-edit policy.
//!
//! ```yaml
//! llm:
//!   policies:
//!     compression:
//!       headroom: true
//!       gcf: false
//! ```

use super::ContextEditPolicy;

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct LocalCompression {
	/// Enable deterministic headroom compression of model-visible text fragments.
	#[serde(default)]
	pub headroom: bool,
	/// Enable deterministic GCF encoding of JSON text fragments.
	#[serde(default)]
	pub gcf: bool,
	/// Analyze-only: log what compression would do (fired fragments, token
	/// savings, prompt-cache invalidation) without rewriting requests. Combine
	/// with `headroom: false` to keep a run as a true uncompressed baseline while
	/// still measuring the compression/cache potential.
	#[serde(default)]
	pub simulate: bool,
}

impl LocalCompression {
	/// Resolve into the runtime [`ContextEditPolicy`]. Runs once at config build.
	pub fn build(self) -> anyhow::Result<ContextEditPolicy> {
		Ok(ContextEditPolicy {
			headroom: self.headroom,
			gcf: self.gcf,
			simulate: self.simulate,
		})
	}
}
