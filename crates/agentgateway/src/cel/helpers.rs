use std::sync::Arc;

use bytes::Bytes;
use cel::Value;
use cel::objects::BytesValue;
use serde::Deserialize;

use super::Expression;

/// Compiles a duration-or-CEL field: an ergonomic duration literal (e.g. `2s`) is wrapped as a CEL
/// `duration(...)` call, otherwise the value is compiled as a CEL expression. Shared by the serde
/// helpers below and by non-serde callers (e.g. XDS translation).
pub fn compile_duration_or_expression(raw: &str) -> anyhow::Result<Arc<Expression>> {
	let expression = if agent_core::durfmt::parse(raw).is_ok() {
		format!("duration({raw:?})")
	} else {
		raw.to_string()
	};
	Ok(Arc::new(Expression::new_strict(&expression)?))
}

/// Serde `deserialize_with` helper for duration-or-CEL fields. See [`compile_duration_or_expression`].
pub fn de_duration_or_expression<'de, D>(deserializer: D) -> Result<Arc<Expression>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let raw = String::deserialize(deserializer)?;
	compile_duration_or_expression(&raw).map_err(serde::de::Error::custom)
}

/// Serde `deserialize_with` helper for optional duration-or-CEL fields.
pub fn de_opt_duration_or_expression<'de, D>(
	deserializer: D,
) -> Result<Option<Arc<Expression>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let Some(raw) = Option::<String>::deserialize(deserializer)? else {
		return Ok(None);
	};
	compile_duration_or_expression(&raw)
		.map(Some)
		.map_err(serde::de::Error::custom)
}

pub fn value_as_byte_or_json(v: Value<'_>) -> anyhow::Result<Bytes> {
	// Materialize Dynamic so nested lookups are converted to concrete values.
	let v = v.always_materialize_owned();
	match &v {
		Value::String(s) => Ok(Bytes::copy_from_slice(s.as_ref().as_bytes())),
		Value::Bytes(BytesValue::Bytes(b)) => Ok(b.clone()),
		Value::Bytes(b) => Ok(Bytes::copy_from_slice(b.as_ref())),
		_ => {
			let js = v.json().map_err(|e| anyhow::anyhow!("{}", e))?;
			let v = serde_json::to_vec(&js)?;
			Ok(Bytes::copy_from_slice(&v))
		},
	}
}
