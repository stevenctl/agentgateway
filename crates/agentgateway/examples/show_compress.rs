//! Show exactly what ctxedit's compressor does to one fragment: detected type,
//! sizes, and the full compressed output — so lossiness is directly visible.
//!
//! Usage: cargo run -p agentgateway --example show_compress -- <fragment.txt> [headroom|gcf|both]

use std::env;
use std::fs;
use std::path::PathBuf;

use agentgateway::llm::ctxedit::dispatch::{self, StrategySet};
use headroom_core::transforms::detect_content_type;

fn main() -> anyhow::Result<()> {
	let mut args = env::args_os().skip(1);
	let path: PathBuf = args.next().map(PathBuf::from).expect("usage: show_compress <file> [strategy]");
	let strat = args.next().and_then(|s| s.into_string().ok()).unwrap_or_else(|| "headroom".into());
	let strategies = match strat.as_str() {
		"headroom" => StrategySet { headroom: true, gcf: false },
		"gcf" => StrategySet { headroom: false, gcf: true },
		"both" => StrategySet { headroom: true, gcf: true },
		_ => anyhow::bail!("strategy must be headroom|gcf|both"),
	};
	let text = fs::read_to_string(&path)?;
	println!("file: {}  detected: {:?}  raw_len: {}", path.display(),
		detect_content_type(&text).content_type, text.len());
	match dispatch::compress_with(&text, strategies) {
		Some((strategy, out)) => {
			println!("STRATEGY: {strategy}   {} -> {} bytes ({:.1}% smaller)\n",
				text.len(), out.len(), 100.0 * (1.0 - out.len() as f64 / text.len() as f64));
			println!("================ COMPRESSED OUTPUT (full) ================\n{out}");
		},
		None => println!("(no compression — passed through unchanged)"),
	}
	Ok(())
}
