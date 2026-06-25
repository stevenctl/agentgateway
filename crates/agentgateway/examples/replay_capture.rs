//! Offline replay of captured upstream requests through the real ctxedit walker.
//!
//! Feed it a `.req.txt` produced by `capture_proxy.py` (or a directory of them).
//! For each request it:
//!   1. Runs the **real** walker (anthropic/completions/responses, chosen by the
//!      request path) + splice, reporting `walked / eligible / compressed` and the
//!      true byte/token savings the gateway would produce *today*.
//!   2. Lists every model-visible string ≥ threshold and shows raw-vs-normalized
//!      compressibility — so you can see what envelope/gutter stripping would
//!      unlock (the walker-normalization work) before changing the impl.
//!
//! This is the offline iteration loop: change ctxedit, `cargo run --example
//! replay_capture -- <captures/>`, watch the numbers move — no live agent run.
//!
//! Usage:
//!   cargo run -p agentgateway --example replay_capture -- <file-or-dir> [headroom|gcf|both]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use agentgateway::llm::ctxedit::dispatch::{self, StrategySet};
use agentgateway::llm::ctxedit::fragments;
use headroom_core::transforms::detect_content_type;
use serde_json::Value;
use tiktoken_rs::CoreBPE;

const MIN_FRAGMENT: usize = 512;

fn bpe() -> &'static CoreBPE {
	static I: OnceLock<CoreBPE> = OnceLock::new();
	I.get_or_init(|| tiktoken_rs::cl100k_base().expect("cl100k tokenizer"))
}
fn toks(s: &str) -> usize {
	bpe().encode_with_special_tokens(s).len()
}
fn pct(before: usize, after: usize) -> f64 {
	if before == 0 {
		0.0
	} else {
		100.0 * (1.0 - after as f64 / before as f64)
	}
}

/// A capture file is: `METHOD /path\n` + headers + `\n\n` + body.
fn split_capture(raw: &[u8]) -> (String, &[u8]) {
	let req_line = raw
		.split(|&b| b == b'\n')
		.next()
		.map(|l| String::from_utf8_lossy(l).trim().to_string())
		.unwrap_or_default();
	let body = raw
		.windows(2)
		.position(|w| w == b"\n\n")
		.map(|i| &raw[i + 2..])
		.unwrap_or(raw);
	(req_line, body)
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
	Anthropic,
	Completions,
	Responses,
}
impl Shape {
	fn name(self) -> &'static str {
		match self {
			Shape::Anthropic => "anthropic",
			Shape::Completions => "completions",
			Shape::Responses => "responses",
		}
	}
}

/// Pick the walker by request path, falling back to body shape.
fn shape_of(req_line: &str, body: &[u8]) -> Shape {
	if req_line.contains("/responses") {
		return Shape::Responses;
	}
	if req_line.contains("/messages") {
		return Shape::Anthropic;
	}
	if req_line.contains("completions") {
		return Shape::Completions;
	}
	// Fall back to body keys.
	if let Ok(v) = serde_json::from_slice::<Value>(body) {
		if v.get("input").is_some() {
			return Shape::Responses;
		}
	}
	Shape::Completions
}

fn walk(shape: Shape, body: &[u8], strategies: StrategySet) -> Option<fragments::Walk> {
	match shape {
		Shape::Anthropic => fragments::anthropic_replacements(body, strategies),
		Shape::Completions => fragments::completions_replacements(body, strategies),
		Shape::Responses => fragments::responses_replacements(body, strategies),
	}
}

// ── normalization strippers (what the walker *could* do to expose payloads) ──

/// mini-swe-agent: `<returncode>N</returncode>\n<output>\nPAYLOAD\n</output>`
/// (or `<output_head>…</output_head> … <output_tail>…</output_tail>` when capped).
fn strip_mini_envelope(s: &str) -> Option<String> {
	if let (Some(a), Some(b)) = (s.find("<output>"), s.rfind("</output>")) {
		if b > a {
			return Some(s[a + "<output>".len()..b].trim().to_string());
		}
	}
	let head = between(s, "<output_head>", "</output_head>");
	let tail = between(s, "<output_tail>", "</output_tail>");
	match (head, tail) {
		(Some(h), Some(t)) => Some(format!("{}\n{}", h.trim(), t.trim())),
		(Some(h), None) => Some(h.trim().to_string()),
		_ => None,
	}
}

/// Codex: `Chunk ID: …\nWall time: …\n…\nOutput:\nPAYLOAD`.
fn strip_codex_envelope(s: &str) -> Option<String> {
	s.split_once("\nOutput:\n")
		.map(|(_, p)| p.to_string())
		.filter(|p| p.len() < s.len())
}

/// `cat -n` / Read gutter: every line is `   <digits>\t<rest>`.
fn strip_numbered_gutter(s: &str) -> Option<String> {
	let mut out = String::with_capacity(s.len());
	let (mut matched, mut total) = (0usize, 0usize);
	for line in s.lines() {
		total += 1;
		let Some((prefix, rest)) = line.trim_start().split_once('\t') else {
			return None;
		};
		if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		matched += 1;
		out.push_str(rest);
		out.push('\n');
	}
	(matched > 0 && matched == total).then_some(out)
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
	let a = s.find(open)? + open.len();
	let b = s[a..].find(close)? + a;
	Some(&s[a..b])
}

/// Collect every string value ≥ MIN_FRAGMENT with a readable path.
fn collect_large_strings(v: &Value, path: &mut String, out: &mut Vec<(String, String)>) {
	match v {
		Value::String(s) if s.len() >= MIN_FRAGMENT => out.push((path.clone(), s.clone())),
		Value::Array(a) => {
			for (i, item) in a.iter().enumerate() {
				let len = path.len();
				path.push_str(&format!("[{i}]"));
				collect_large_strings(item, path, out);
				path.truncate(len);
			}
		},
		Value::Object(m) => {
			for (k, val) in m {
				let len = path.len();
				if !path.is_empty() {
					path.push('.');
				}
				path.push_str(k);
				collect_large_strings(val, path, out);
				path.truncate(len);
			}
		},
		_ => {},
	}
}

fn try_one(text: &str, strategies: StrategySet) -> Option<(&'static str, usize, usize)> {
	dispatch::compress_with(text, strategies)
		.map(|(strategy, out)| (strategy, out.len(), toks(&out)))
}

#[derive(Default)]
struct Agg {
	files: usize,
	walked: usize,
	eligible: usize,
	compressed: usize,
	bytes_before: usize,
	bytes_after: usize,
	tok_before: usize,
	tok_after: usize,
}

fn process(path: &Path, strategies: StrategySet, agg: &mut Agg) {
	let Ok(raw) = fs::read(path) else {
		return;
	};
	let (req_line, body) = split_capture(&raw);
	let shape = shape_of(&req_line, body);

	let body_str = String::from_utf8_lossy(body);
	let body_tok = toks(&body_str);
	println!(
		"\n=== {} [{}] {}B / {}tok ===",
		path.file_name().unwrap_or_default().to_string_lossy(),
		shape.name(),
		body.len(),
		body_tok,
	);

	// ── 1. real walker: what the gateway does today ──
	if let Some(w) = walk(shape, body, strategies) {
		let compressed = w.replacements.len();
		let new_body = fragments::apply_string_replacements(body, w.replacements);
		let (after_b, after_t) = match &new_body {
			Some(nb) => (nb.len(), toks(&String::from_utf8_lossy(nb))),
			None => (body.len(), body_tok),
		};
		println!(
			"  real walker: walked={} eligible={} compressed={}  bytes {}->{} ({:.1}%)  tok {}->{} ({:.1}%)",
			w.walked,
			w.eligible,
			compressed,
			body.len(),
			after_b,
			pct(body.len(), after_b),
			body_tok,
			after_t,
			pct(body_tok, after_t),
		);
		agg.walked += w.walked;
		agg.eligible += w.eligible;
		agg.compressed += compressed;
		agg.bytes_before += body.len();
		agg.bytes_after += after_b;
		agg.tok_before += body_tok;
		agg.tok_after += after_t;
	} else {
		println!("  real walker: no match (unparsed / wrong shape)");
		agg.bytes_before += body.len();
		agg.bytes_after += body.len();
		agg.tok_before += body_tok;
		agg.tok_after += body_tok;
	}
	agg.files += 1;

	// ── 2. per-fragment what-if: raw vs normalized ──
	let Ok(v) = serde_json::from_slice::<Value>(body) else {
		return;
	};
	let mut frags = Vec::new();
	collect_large_strings(&v, &mut String::new(), &mut frags);
	if frags.is_empty() {
		return;
	}
	println!("  fragments >= {MIN_FRAGMENT}B (raw vs best normalization):");
	for (loc, text) in &frags {
		let detected = format!("{:?}", detect_content_type(text).content_type);
		let raw = try_one(text, strategies);
		let raw_str = match raw {
			Some((s, b, _)) => format!("HIT {s} {:.0}%", pct(text.len(), b)),
			None => "miss".to_string(),
		};
		// try each normalization; keep the best (smallest) hit.
		let mut best: Option<(&str, &'static str, usize)> = None;
		for (label, norm) in [
			("mini", strip_mini_envelope(text)),
			("codex", strip_codex_envelope(text)),
			("gutter", strip_numbered_gutter(text)),
		] {
			if let Some(n) = norm {
				if let Some((s, b, _)) = try_one(&n, strategies) {
					if best.is_none_or(|(_, _, bb)| b < bb) {
						best = Some((label, s, b));
					}
				}
			}
		}
		let norm_str = match best {
			Some((label, s, b)) => format!("{label}-strip->{s} {:.0}%", pct(text.len(), b)),
			None => "—".to_string(),
		};
		println!(
			"    {:<32} {:>8}B {:<12} raw:{:<18} norm:{}",
			truncate(loc, 32),
			text.len(),
			detected,
			raw_str,
			norm_str,
		);
	}
}

fn truncate(s: &str, n: usize) -> String {
	if s.len() <= n {
		s.to_string()
	} else {
		format!("…{}", &s[s.len() - n + 1..])
	}
}

fn main() -> anyhow::Result<()> {
	let mut args = env::args_os().skip(1);
	let path = args
		.next()
		.map(PathBuf::from)
		.expect("usage: replay_capture <file-or-dir> [headroom|gcf|both]");
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

	let mut files: Vec<PathBuf> = if path.is_dir() {
		fs::read_dir(&path)?
			.filter_map(|e| e.ok().map(|e| e.path()))
			.filter(|p| p.to_string_lossy().ends_with(".req.txt"))
			.collect()
	} else {
		vec![path.clone()]
	};
	files.sort();

	println!("replay: {} ({} file(s)), strategy={strategy_name}", path.display(), files.len());
	let mut agg = Agg::default();
	for f in &files {
		process(f, strategies, &mut agg);
	}

	println!("\n==================== AGGREGATE ({} files) ====================", agg.files);
	println!(
		"  fragments: walked={} eligible(>=512B)={} compressed={}",
		agg.walked, agg.eligible, agg.compressed
	);
	println!(
		"  request bytes : {} -> {}  ({:.1}% saved)",
		agg.bytes_before,
		agg.bytes_after,
		pct(agg.bytes_before, agg.bytes_after)
	);
	println!(
		"  request tokens: {} -> {}  ({:.1}% saved)",
		agg.tok_before,
		agg.tok_after,
		pct(agg.tok_before, agg.tok_after)
	);
	Ok(())
}
