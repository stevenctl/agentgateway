use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use agentgateway::llm::ctxedit::dispatch::{self, StrategySet};
use tiktoken_rs::CoreBPE;

fn bpe() -> &'static CoreBPE {
	static I: OnceLock<CoreBPE> = OnceLock::new();
	I.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k tokenizer"))
}

fn toks(s: &str) -> usize {
	bpe().encode_with_special_tokens(s).len()
}

fn strategies(name: &str) -> anyhow::Result<StrategySet> {
	match name {
		"headroom" => Ok(StrategySet {
			headroom: true,
			gcf: false,
		}),
		"gcf" => Ok(StrategySet {
			headroom: false,
			gcf: true,
		}),
		"both" => Ok(StrategySet {
			headroom: true,
			gcf: true,
		}),
		_ => anyhow::bail!("strategy must be headroom, gcf, or both"),
	}
}

fn strip_numbered_gutter(text: &str) -> Option<String> {
	let mut stripped = String::with_capacity(text.len());
	let mut matched = 0usize;
	let mut total = 0usize;
	for line in text.lines() {
		total += 1;
		let trimmed = line.trim_start();
		let Some((prefix, rest)) = trimmed.split_once('\t') else {
			return None;
		};
		if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		matched += 1;
		stripped.push_str(rest);
		stripped.push('\n');
	}
	(matched > 0 && matched == total).then_some(stripped)
}

fn attempt(label: &str, text: &str, strategies: StrategySet) {
	print!("{label:<18} {:>8}B {:>7}tok", text.len(), toks(text));
	if let Some((strategy, out)) = dispatch::compress_with(text, strategies) {
		println!(
			"  HIT {strategy:<15} {:>8}B {:>7}tok saved {:>5.1}% bytes {:>5.1}% tok",
			out.len(),
			toks(&out),
			100.0 * (1.0 - out.len() as f64 / text.len() as f64),
			100.0 * (1.0 - toks(&out) as f64 / toks(text) as f64),
		);
	} else {
		println!("  miss");
	}
}

fn main() -> anyhow::Result<()> {
	let mut args = env::args_os().skip(1);
	let path = args
		.next()
		.map(PathBuf::from)
		.expect("usage: fixture_compressibility <path> [headroom|gcf|both]");
	let strategy_name = args
		.next()
		.and_then(|s| s.into_string().ok())
		.unwrap_or_else(|| "both".to_string());
	let strategies = strategies(&strategy_name)?;
	let text = fs::read_to_string(&path)?;

	println!("fixture : {}", path.display());
	println!("strategy: {strategy_name}");
	attempt("raw", &text, strategies);
	if let Some(stripped) = strip_numbered_gutter(&text) {
		attempt("gutter-stripped", &stripped, strategies);
	}
	if path.extension().is_some_and(|ext| ext == "jsonl") {
		let wrapped = format!(
			"[{}]",
			text
				.lines()
				.filter(|line| !line.trim().is_empty())
				.collect::<Vec<_>>()
				.join(",")
		);
		attempt("jsonl-as-array", &wrapped, strategies);
	}
	Ok(())
}
