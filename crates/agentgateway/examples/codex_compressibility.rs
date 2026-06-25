use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::OnceLock;

use agentgateway::llm::ctxedit::dispatch::{self, StrategySet};
use headroom_core::transforms::{
	ContentType, DiffCompressor, DiffCompressorConfig, LogCompressor, LogCompressorConfig,
	SearchCompressor, SearchCompressorConfig, detect_content_type,
};
use serde_json::Value;
use tiktoken_rs::CoreBPE;

fn bpe() -> &'static CoreBPE {
	static I: OnceLock<CoreBPE> = OnceLock::new();
	I.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k tokenizer"))
}

fn toks(s: &str) -> usize {
	bpe().encode_with_special_tokens(s).len()
}

fn output_text(raw: &Value) -> Option<String> {
	match raw {
		Value::String(s) => {
			if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(s) {
				if let Some(Value::String(output)) = obj.get("output") {
					return Some(output.clone());
				}
				if !obj.is_empty() {
					return Some(Value::Object(obj).to_string());
				}
			}
			Some(s.clone())
		},
		Value::Object(obj) => {
			if let Some(Value::String(output)) = obj.get("output") {
				return Some(output.clone());
			}
			if obj.is_empty() {
				None
			} else {
				Some(raw.to_string())
			}
		},
		Value::Null => None,
		_ => Some(raw.to_string()),
	}
}

#[derive(Default)]
struct Summary {
	outputs: usize,
	eligible: usize,
	fired: usize,
	before_bytes: usize,
	after_bytes: usize,
	before_tokens: usize,
	after_tokens: usize,
}

fn payload_after_codex_envelope(text: &str) -> Option<&str> {
	text
		.split_once("\nOutput:\n")
		.map(|(_, payload)| payload)
		.filter(|payload| payload.len() < text.len())
}

fn record_attempt(
	summary: &mut Summary,
	rows: &mut Vec<(String, usize, usize, usize, usize, &'static str)>,
	text: &str,
	call_id: &str,
	strategies: StrategySet,
) -> bool {
	if text.len() < 512 {
		return false;
	}
	summary.eligible += 1;
	let before_toks = toks(text);
	if let Some((strategy, compressed)) = dispatch::compress_with(text, strategies) {
		let after_toks = toks(&compressed);
		summary.fired += 1;
		summary.before_bytes += text.len();
		summary.after_bytes += compressed.len();
		summary.before_tokens += before_toks;
		summary.after_tokens += after_toks;
		rows.push((
			call_id.to_string(),
			text.len(),
			compressed.len(),
			before_toks,
			after_toks,
			strategy,
		));
		return true;
	}
	false
}

fn main() -> anyhow::Result<()> {
	let mut args = env::args_os().skip(1);
	let path = args
		.next()
		.map(PathBuf::from)
		.expect("usage: codex_compressibility <codex-session.jsonl> [headroom|gcf|both]");
	let strategy_name = args
		.next()
		.and_then(|s| s.into_string().ok())
		.unwrap_or_else(|| "headroom".to_string());
	let strategies = match strategy_name.as_str() {
		"headroom" => StrategySet {
			headroom: true,
			gcf: false,
		},
		"gcf" => StrategySet {
			headroom: false,
			gcf: true,
		},
		"both" => StrategySet {
			headroom: true,
			gcf: true,
		},
		_ => anyhow::bail!("strategy must be headroom, gcf, or both"),
	};
	let file = File::open(&path)?;
	let mut summary = Summary::default();
	let mut rows: Vec<(String, usize, usize, usize, usize, &'static str)> = Vec::new();
	let mut payload_summary = Summary::default();
	let mut payload_rows: Vec<(String, usize, usize, usize, usize, &'static str)> = Vec::new();
	let log_compressor = LogCompressor::new(LogCompressorConfig::default());
	let search_compressor = SearchCompressor::new(SearchCompressorConfig::default());
	let diff_compressor = DiffCompressor::new(DiffCompressorConfig::default());
	let mut noops: Vec<(String, usize, usize, String, String, String)> = Vec::new();

	for line in BufReader::new(file).lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}
		let event: Value = serde_json::from_str(&line)?;
		let Some(payload) = event.get("payload") else {
			continue;
		};
		let Some(payload_type) = payload.get("type").and_then(Value::as_str) else {
			continue;
		};
		if payload_type != "function_call_output" && payload_type != "custom_tool_call_output" {
			continue;
		}

		let Some(text) = payload.get("output").and_then(output_text) else {
			continue;
		};
		summary.outputs += 1;
		let call_id = payload
			.get("call_id")
			.and_then(Value::as_str)
			.unwrap_or("")
			.to_string();
		if let Some(payload_text) = payload_after_codex_envelope(&text) {
			payload_summary.outputs += 1;
			record_attempt(
				&mut payload_summary,
				&mut payload_rows,
				payload_text,
				&call_id,
				strategies,
			);
		}
		if text.len() < 512 {
			continue;
		}
		let before_toks = toks(&text);
		if record_attempt(&mut summary, &mut rows, &text, &call_id, strategies) {
		} else {
			let detected_type = detect_content_type(&text).content_type;
			let attempted = match detected_type {
				ContentType::BuildOutput => {
					let (out, _) = log_compressor.compress(&text, 0.0);
					format!(
						"attempted {}B, {}tok",
						out.compressed.len(),
						toks(&out.compressed)
					)
				},
				ContentType::SearchResults => {
					let (out, _) = search_compressor.compress(&text, "", 0.0);
					format!(
						"attempted {}B, {}tok",
						out.compressed.len(),
						toks(&out.compressed)
					)
				},
				ContentType::GitDiff => {
					let out = diff_compressor.compress(&text, "");
					format!(
						"attempted {}B, {}tok",
						out.compressed.len(),
						toks(&out.compressed)
					)
				},
				_ => "unsupported by dispatcher".to_string(),
			};
			let detected = format!("{detected_type:?}");
			let preview = text
				.chars()
				.take(180)
				.collect::<String>()
				.replace('\n', "\\n");
			noops.push((
				call_id,
				text.len(),
				before_toks,
				detected,
				attempted,
				preview,
			));
		}
	}

	println!("codex session: {}", path.display());
	println!("strategy     : {strategy_name}");
	println!("  outputs seen      : {}", summary.outputs);
	println!("  eligible >=512B   : {}", summary.eligible);
	println!("  would compress    : {}", summary.fired);
	println!(
		"  bytes             : {:>10} -> {:>10}  saved {:>10} ({:.1}%)",
		summary.before_bytes,
		summary.after_bytes,
		summary.before_bytes.saturating_sub(summary.after_bytes),
		if summary.before_bytes == 0 {
			0.0
		} else {
			100.0 * (1.0 - summary.after_bytes as f64 / summary.before_bytes as f64)
		}
	);
	println!(
		"  tokens (cl100k)   : {:>10} -> {:>10}  saved {:>10} ({:.1}%)",
		summary.before_tokens,
		summary.after_tokens,
		summary.before_tokens.saturating_sub(summary.after_tokens),
		if summary.before_tokens == 0 {
			0.0
		} else {
			100.0 * (1.0 - summary.after_tokens as f64 / summary.before_tokens as f64)
		}
	);

	if !rows.is_empty() {
		println!();
		println!("  compressed outputs:");
		for (call_id, before_b, after_b, before_t, after_t, strategy) in rows {
			println!(
				"    {call_id} {strategy}: {before_b}B -> {after_b}B, {before_t}tok -> {after_t}tok"
			);
		}
	}
	if !noops.is_empty() {
		println!();
		println!("  eligible but not compressed:");
		for (call_id, bytes, tokens, detected, attempted, preview) in noops {
			println!(
				"    {call_id} {detected}: {bytes}B, {tokens}tok, {attempted}, preview=\"{preview}\""
			);
		}
	}

	println!();
	println!("codex envelope stripped:");
	println!("  outputs with payload: {}", payload_summary.outputs);
	println!("  eligible >=512B     : {}", payload_summary.eligible);
	println!("  would compress      : {}", payload_summary.fired);
	println!(
		"  bytes               : {:>10} -> {:>10}  saved {:>10} ({:.1}%)",
		payload_summary.before_bytes,
		payload_summary.after_bytes,
		payload_summary
			.before_bytes
			.saturating_sub(payload_summary.after_bytes),
		if payload_summary.before_bytes == 0 {
			0.0
		} else {
			100.0 * (1.0 - payload_summary.after_bytes as f64 / payload_summary.before_bytes as f64)
		}
	);
	println!(
		"  tokens (cl100k)     : {:>10} -> {:>10}  saved {:>10} ({:.1}%)",
		payload_summary.before_tokens,
		payload_summary.after_tokens,
		payload_summary
			.before_tokens
			.saturating_sub(payload_summary.after_tokens),
		if payload_summary.before_tokens == 0 {
			0.0
		} else {
			100.0 * (1.0 - payload_summary.after_tokens as f64 / payload_summary.before_tokens as f64)
		}
	);
	if !payload_rows.is_empty() {
		println!();
		println!("  compressed payloads:");
		for (call_id, before_b, after_b, before_t, after_t, strategy) in payload_rows {
			println!(
				"    {call_id} {strategy}: {before_b}B -> {after_b}B, {before_t}tok -> {after_t}tok"
			);
		}
	}

	Ok(())
}
