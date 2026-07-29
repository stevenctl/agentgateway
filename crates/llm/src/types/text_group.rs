use std::ops::Range;

/// A group of text blocks that are part of the same message and should be joined
/// for editing but split back to preserve the original structure.
pub struct TextGroup<'a> {
	inner: Inner<'a>,
}

enum Inner<'a> {
	/// Fast path: 0/1 blocks means no join buffer and edits apply in place.
	Single {
		text: Option<&'a mut String>,
		changed: bool,
	},
	Multi {
		parts: Vec<&'a mut String>,
		buf: String,
		/// Where each part currently lives inside `buf`.
		spans: Vec<Range<usize>>,
	},
}

impl<'a> TextGroup<'a> {
	pub fn single(text: &'a mut String) -> Self {
		Self {
			inner: Inner::Single {
				text: Some(text),
				changed: false,
			},
		}
	}

	/// Join with `sep` only when the accumulated text is non-empty (fold parity).
	pub fn folded(sep: &str, parts: Vec<&'a mut String>) -> Self {
		Self::build(sep, parts, false)
	}

	/// Join with `sep` between every pair of parts (`.join()` parity).
	pub fn joined(sep: &str, parts: Vec<&'a mut String>) -> Self {
		Self::build(sep, parts, true)
	}

	fn build(sep: &str, mut parts: Vec<&'a mut String>, sep_always: bool) -> Self {
		if parts.len() <= 1 {
			return Self {
				inner: Inner::Single {
					text: parts.pop(),
					changed: false,
				},
			};
		}
		let mut buf = String::with_capacity(
			parts.iter().map(|p| p.len()).sum::<usize>() + sep.len() * (parts.len() - 1),
		);
		let mut spans = Vec::with_capacity(parts.len());
		for p in parts.iter() {
			if sep_always && !spans.is_empty() || !buf.is_empty() {
				buf.push_str(sep);
			}
			let start = buf.len();
			buf.push_str(p);
			spans.push(start..buf.len());
		}
		Self {
			inner: Inner::Multi { parts, buf, spans },
		}
	}

	pub fn text(&self) -> &str {
		match &self.inner {
			Inner::Single { text, .. } => text.as_ref().map(|t| t.as_str()).unwrap_or(""),
			Inner::Multi { buf, .. } => buf,
		}
	}

	/// Replace `range` of the joined text with `repl`, keeping part boundaries in sync. The
	/// replacement is never split: it lands wholly in the first part the range overlaps; parts the
	/// range fully consumes are left empty (callers drop them in `finish`). Returns whether a
	/// replacement was applied — zero-width ranges mask nothing and are skipped.
	pub fn replace_range(&mut self, range: Range<usize>, repl: &str) -> bool {
		if range.is_empty() {
			return false;
		}
		match &mut self.inner {
			Inner::Single { text, changed } => {
				if let Some(text) = text {
					text.replace_range(range, repl);
					*changed = true;
				}
			},
			Inner::Multi { buf, spans, .. } => {
				let delta = repl.len() as isize - range.len() as isize;
				let repl_end = range.start + repl.len();
				let shift = |x: usize| -> usize {
					if x >= range.end {
						x.checked_add_signed(delta).expect("span shift overflow")
					} else if x > range.start {
						repl_end
					} else {
						x
					}
				};
				buf.replace_range(range.clone(), repl);
				let mut taken = false;
				for sp in spans {
					// an empty part owns no bytes and can never claim the replacement
					let overlaps = sp.start < sp.end && sp.start < range.end && sp.end > range.start;
					*sp = if !overlaps {
						shift(sp.start)..shift(sp.end)
					} else {
						let end = if sp.end >= range.end {
							sp.end
								.checked_add_signed(delta)
								.expect("span shift overflow")
						} else {
							repl_end
						};
						if !taken {
							taken = true;
							// this part owns the replacement; grow left over a separator-leading match
							sp.start.min(range.start)..end
						} else {
							// later parts keep only their surviving tail
							repl_end..end
						}
					};
				}
			},
		}
		true
	}

	/// Write the joined text back into the parts. Returns whether any part's text changed; a
	/// replacement that only touched separator bytes changes nothing real.
	pub fn finish(self) -> bool {
		match self.inner {
			Inner::Single { changed, .. } => changed,
			Inner::Multi { parts, buf, spans } => {
				let mut changed = false;
				for (p, sp) in parts.into_iter().zip(spans) {
					let new = &buf[sp];
					if p != new {
						p.clear();
						p.push_str(new);
						changed = true;
					}
				}
				changed
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn owned(v: &[&str]) -> Vec<String> {
		v.iter().map(|s| s.to_string()).collect()
	}

	fn run(sep: &str, parts: &mut [String], ranges: &[Range<usize>]) -> bool {
		let mut g = TextGroup::folded(sep, parts.iter_mut().collect());
		// descending order, as the guard applies them
		for r in ranges.iter().rev() {
			g.replace_range(r.clone(), "<X>");
		}
		g.finish()
	}

	#[test]
	fn cross_block_match_masks_across_boundary() {
		let mut parts = owned(&["Please use this secret", "token to authenticate"]);
		let joined = "Please use this secret token to authenticate";
		let start = joined.find("secret token").unwrap();
		assert!(run(" ", &mut parts, &[start..start + "secret token".len()]));
		assert_eq!(parts, owned(&["Please use this <X>", " to authenticate"]));
	}

	#[test]
	fn straddling_match_places_placeholder_once() {
		let mut parts = owned(&["credit card pin 1", "23 for later"]);
		assert!(run("", &mut parts, &[16..19]));
		assert_eq!(parts, owned(&["credit card pin <X>", " for later"]));
	}

	#[test]
	fn fully_consumed_parts_are_left_empty() {
		let mut parts = owned(&["xxAB", "MID", "CDyy"]);
		assert!(run("", &mut parts, &[2..9]));
		assert_eq!(parts, owned(&["xx<X>", "", "yy"]));
	}

	#[test]
	fn match_inside_separator_changes_nothing() {
		let mut parts = owned(&["abc", "def"]);
		assert!(!run(" | ", &mut parts, &[4..5]));
		assert_eq!(parts, owned(&["abc", "def"]));
	}

	#[test]
	fn match_overlapping_separator_edges() {
		let mut parts = owned(&["abc", "def"]);
		// "c d" across the boundary
		assert!(run(" ", &mut parts, &[2..5]));
		assert_eq!(parts, owned(&["ab<X>", "ef"]));
	}

	#[test]
	fn zero_width_match_is_a_noop() {
		for at in 0..=5 {
			let mut parts = owned(&["ab", "cd"]);
			let mut g = TextGroup::folded(" ", parts.iter_mut().collect());
			assert!(!g.replace_range(at..at, "<X>"));
			assert!(!g.finish());
			assert_eq!(parts, owned(&["ab", "cd"]));
		}
	}

	#[test]
	fn single_is_in_place() {
		let mut text = "my ssn 123".to_string();
		let mut g = TextGroup::single(&mut text);
		assert!(g.replace_range(7..10, "<X>"));
		assert!(g.finish());
		assert_eq!(text, "my ssn <X>");
	}

	#[test]
	fn one_part_group_takes_fast_path() {
		let mut parts = owned(&["only"]);
		let mut g = TextGroup::folded("\n", parts.iter_mut().collect());
		assert!(matches!(g.inner, Inner::Single { .. }));
		g.replace_range(0..4, "<X>");
		assert!(g.finish());
		assert_eq!(parts, owned(&["<X>"]));
	}

	#[test]
	fn empty_group_is_empty() {
		let g = TextGroup::folded(" ", vec![]);
		assert_eq!(g.text(), "");
		assert!(!g.finish());
	}

	#[test]
	fn folded_skips_separator_while_empty_joined_does_not() {
		let mut a = owned(&["", "ab"]);
		assert_eq!(TextGroup::folded(" ", a.iter_mut().collect()).text(), "ab");
		let mut b = owned(&["", "ab"]);
		assert_eq!(
			TextGroup::joined("\n", b.iter_mut().collect()).text(),
			"\nab"
		);
		// mid-list empties separate in both
		let mut c = owned(&["a", "", "b"]);
		assert_eq!(
			TextGroup::folded(" ", c.iter_mut().collect()).text(),
			"a  b"
		);
	}

	#[test]
	fn multibyte_text_shifts_correctly() {
		let mut parts = owned(&["秘密は🙂", "です x"]);
		let joined = "秘密は🙂 です x";
		let start = joined.find("🙂 で").unwrap();
		assert!(run(" ", &mut parts, &[start..start + "🙂 で".len()]));
		assert_eq!(parts, owned(&["秘密は<X>", "す x"]));
	}

	#[test]
	fn multiple_matches_in_reverse_order() {
		let mut parts = owned(&["xA", "By", "zC", "Dw"]);
		// "AB" and "CD" both straddle
		assert!(run("", &mut parts, &[1..3, 5..7]));
		assert_eq!(parts, owned(&["x<X>", "y", "z<X>", "w"]));
	}

	// Independent oracle: tag every byte of the joined text with its owning part (None for
	// separators); a replacement's bytes take the first owner the range overlaps. Shares no code
	// with the span arithmetic.
	struct Oracle {
		buf: Vec<u8>,
		tags: Vec<Option<usize>>,
		nparts: usize,
	}

	impl Oracle {
		fn new(sep: &str, parts: &[String]) -> Self {
			let mut buf = Vec::new();
			let mut tags = Vec::new();
			for (i, p) in parts.iter().enumerate() {
				if !buf.is_empty() {
					buf.extend_from_slice(sep.as_bytes());
					tags.extend(std::iter::repeat(None).take(sep.len()));
				}
				buf.extend_from_slice(p.as_bytes());
				tags.extend(std::iter::repeat(Some(i)).take(p.len()));
			}
			Self {
				buf,
				tags,
				nparts: parts.len(),
			}
		}

		fn replace_range(&mut self, r: Range<usize>, repl: &str) {
			if r.is_empty() {
				return;
			}
			let owner = self.tags[r.clone()].iter().find_map(|t| *t);
			self.buf.splice(r.clone(), repl.bytes());
			self
				.tags
				.splice(r, std::iter::repeat(owner).take(repl.len()));
		}

		fn parts(&self) -> Vec<String> {
			let mut out = vec![Vec::new(); self.nparts];
			for (b, t) in self.buf.iter().zip(&self.tags) {
				if let Some(i) = t {
					out[*i].push(*b);
				}
			}
			out
				.into_iter()
				.map(|b| String::from_utf8(b).unwrap())
				.collect()
		}
	}

	struct Rng(u64);

	impl Rng {
		fn below(&mut self, n: usize) -> usize {
			let mut x = self.0;
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			self.0 = x;
			(x % n as u64) as usize
		}
	}

	#[test]
	fn randomized_matches_oracle() {
		const ALPHA: &[&str] = &["a", "b", "-", " ", "中", "🙂"];
		const SEPS: &[&str] = &["", " ", "\n", " || "];
		const REPLS: &[&str] = &["<X>", "<SSN>", "!", "<a-longer-placeholder>"];

		let mut rng = Rng(0x5EED_1234_9ABC_DEF1);
		for _ in 0..10_000 {
			let nparts = 2 + rng.below(5);
			let parts: Vec<String> = (0..nparts)
				.map(|_| {
					let len = rng.below(6);
					(0..len).map(|_| ALPHA[rng.below(ALPHA.len())]).collect()
				})
				.collect();
			let sep = SEPS[rng.below(SEPS.len())];
			let repl = REPLS[rng.below(REPLS.len())];

			let mut subject = parts.clone();
			let mut g = TextGroup::folded(sep, subject.iter_mut().collect());
			let mut o = Oracle::new(sep, &parts);
			assert_eq!(g.text(), std::str::from_utf8(&o.buf).unwrap());

			// random non-overlapping char-aligned ranges, applied descending
			let n = g.text().len();
			let mut ranges: Vec<Range<usize>> = Vec::new();
			let mut at = 0usize;
			while at <= n {
				let mut start = at + rng.below(4);
				while start < n && !g.text().is_char_boundary(start) {
					start += 1;
				}
				if start > n {
					break;
				}
				let mut end = start + rng.below(5);
				while end < n && !g.text().is_char_boundary(end) {
					end += 1;
				}
				let end = end.min(n);
				ranges.push(start..end);
				at = end + 1;
			}
			for r in ranges.iter().rev() {
				g.replace_range(r.clone(), repl);
				o.replace_range(r.clone(), repl);
			}
			g.finish();
			assert_eq!(
				subject,
				o.parts(),
				"diverged from oracle: parts={parts:?} sep={sep:?} ranges={ranges:?}"
			);
		}
	}
}
