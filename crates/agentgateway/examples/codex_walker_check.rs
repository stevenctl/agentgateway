//! End-to-end check that the Responses walker reaches Codex tool outputs.
//!
//! Reconstructs a real OpenAI Responses request body (`{"model", "input":[...]}`)
//! from a Codex session JSONL, then runs both orchestrators on it:
//!   - `completions::compress` — the pre-fix path for OpenAI-family providers.
//!     A Responses body has `input`, not `messages`, so this must no-op (None).
//!   - `responses::compress` — the new walker. Should rewrite `input[]` tool
//!     outputs and return a smaller body.
//!
//! Usage: codex_walker_check <codex-session.jsonl> [headroom|gcf|both]

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use agentgateway::llm::ctxedit::dispatch::StrategySet;
use agentgateway::llm::ctxedit::{completions, responses};
use serde_json::{Value, json};

fn main() -> anyhow::Result<()> {
	let mut args = env::args_os().skip(1);
	let path = args
		.next()
		.map(PathBuf::from)
		.expect("usage: codex_walker_check <codex-session.jsonl> [headroom|gcf|both]");
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

	// Collect the Responses input items (tool outputs + message turns) in order.
	let mut items: Vec<Value> = Vec::new();
	for line in BufReader::new(File::open(&path)?).lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}
		let event: Value = serde_json::from_str(&line)?;
		let Some(payload) = event.get("payload") else {
			continue;
		};
		match payload.get("type").and_then(Value::as_str) {
			Some("function_call_output" | "custom_tool_call_output" | "message") => {
				items.push(payload.clone());
			},
			_ => {},
		}
	}

	let body = serde_json::to_vec(&json!({
		"model": "gpt-5-codex",
		"input": items,
	}))?;

	let completions_out = completions::compress(&body, strategies);
	let responses_out = responses::compress(&body, strategies);

	println!("codex session : {}", path.display());
	println!("strategy      : {strategy_name}");
	println!("input items   : {}", items.len());
	println!("request bytes : {}", body.len());
	println!();
	println!(
		"completions::compress (pre-fix OpenAI path) : {}",
		match &completions_out {
			Some(_) => "Some(..)  <- UNEXPECTED",
			None => "None  (no `messages[]` — correctly no-ops)",
		}
	);
	match &responses_out {
		Some(out) => {
			let saved = body.len().saturating_sub(out.len());
			println!(
				"responses::compress  (new walker)           : Some -> {} -> {} bytes, saved {} ({:.1}%)",
				body.len(),
				out.len(),
				saved,
				100.0 * (saved as f64 / body.len() as f64),
			);
			// Re-parse to confirm we produced a still-valid Responses body.
			let reparsed: Value = serde_json::from_slice(out)?;
			let n_input = reparsed
				.get("input")
				.and_then(Value::as_array)
				.map(|a| a.len())
				.unwrap_or(0);
			println!(
				"                                              (re-parsed OK, {n_input} input items preserved)"
			);
		},
		None => println!("responses::compress  (new walker)           : None  <- nothing compressed"),
	}

	Ok(())
}
