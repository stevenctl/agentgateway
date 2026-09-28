use anyhow::{Context, ensure};
use bytes::Bytes;
use serde_json::{Map, Value};

use crate::http::{Body, HeaderMap};

pub(super) trait Sink {
	/// Content passed through unchanged: multipart framing, other fields, and non-batch files.
	async fn raw(&mut self, bytes: Bytes) -> anyhow::Result<()>;
	/// A record from a batch input file.
	async fn record(&mut self, url: String, record: Map<String, Value>) -> anyhow::Result<()>;
}

#[derive(Debug, thiserror::Error)]
#[error("batch record exceeds the size limit")]
pub(super) struct RecordTooLarge;

pub(super) struct Summary {
	/// Whether the `purpose` field is `batch`.
	pub batch: bool,
	pub filename: Option<String>,
	pub file_bytes: usize,
	pub records: usize,
}

pub(super) fn multipart(
	headers: &HeaderMap,
	body: Body,
) -> anyhow::Result<(multer::Multipart<'static>, String)> {
	let content_type = headers
		.get(::http::header::CONTENT_TYPE)
		.context("missing content-type")?
		.to_str()?;
	let boundary = multer::parse_boundary(content_type)?;
	let stream = http_body_util::BodyExt::into_data_stream(body);
	Ok((multer::Multipart::new(stream, boundary.clone()), boundary))
}

/// Walks a multipart upload, splitting batch input files into records.
///
/// A file is batch input if a preceding `purpose` field is `batch`, or otherwise if its first line
/// is a record. Batch input must contain only records. `always_batch` requires every file to be
/// batch input.
pub(super) async fn walk(
	mut multipart: multer::Multipart<'static>,
	boundary: &str,
	max_record: usize,
	always_batch: bool,
	sink: &mut impl Sink,
) -> anyhow::Result<Summary> {
	let mut purpose: Option<bool> = None;
	let mut filename = None;
	let mut file_bytes = 0;
	let mut records = 0;
	let mut unprocessed_file = false;
	while let Some(mut field) = multipart.next_field().await? {
		let name = field
			.name()
			.context("upload fields must be named")?
			.to_owned();
		// Parts are re-emitted with their original headers so the provider sees the same fields.
		let mut head = format!("--{boundary}\r\n").into_bytes();
		for (header, value) in field.headers() {
			head.extend_from_slice(header.as_str().as_bytes());
			head.extend_from_slice(b": ");
			head.extend_from_slice(value.as_bytes());
			head.extend_from_slice(b"\r\n");
		}
		head.extend_from_slice(b"\r\n");
		sink.raw(head.into()).await?;
		match name.as_str() {
			"file" => {
				ensure!(filename.is_none(), "only one file is supported");
				filename = Some(field.file_name().unwrap_or("input.jsonl").to_owned());
				if always_batch {
					ensure!(purpose != Some(false), "purpose must be batch");
				}
				let mut file = File {
					batch: if always_batch { Some(true) } else { purpose },
					line: Vec::new(),
					max_record,
					bytes: 0,
					records: 0,
				};
				while let Some(chunk) = field.chunk().await? {
					file.chunk(chunk, sink).await?;
				}
				file.finish(sink).await?;
				file_bytes = file.bytes;
				records = file.records;
				unprocessed_file = file.batch == Some(false);
			},
			"purpose" => {
				ensure!(purpose.is_none(), "only one purpose is supported");
				// Only enough of the value is kept to tell whether it is exactly "batch".
				let limit = b"batch".len() + 1;
				let mut value = Vec::new();
				while let Some(chunk) = field.chunk().await? {
					let keep = chunk.len().min(limit.saturating_sub(value.len()));
					value.extend_from_slice(&chunk[..keep]);
					sink.raw(chunk).await?;
				}
				purpose = Some(value == b"batch");
			},
			_ => {
				while let Some(chunk) = field.chunk().await? {
					sink.raw(chunk).await?;
				}
			},
		}
		sink.raw(Bytes::from_static(b"\r\n")).await?;
	}
	// The closing boundary completes a passthrough upload, so a batch file that was not processed
	// is rejected before it is sent.
	ensure!(
		!(unprocessed_file && purpose == Some(true)),
		"batch input must contain only batch records"
	);
	sink.raw(format!("--{boundary}--\r\n").into()).await?;
	Ok(Summary {
		batch: purpose == Some(true),
		filename,
		file_bytes,
		records,
	})
}

struct File {
	/// Whether this is batch input; undecided until the first line when the purpose is unknown.
	batch: Option<bool>,
	line: Vec<u8>,
	max_record: usize,
	bytes: usize,
	records: usize,
}

impl File {
	async fn chunk(&mut self, mut chunk: Bytes, sink: &mut impl Sink) -> anyhow::Result<()> {
		self.bytes += chunk.len();
		while !chunk.is_empty() {
			if self.batch == Some(false) {
				return sink.raw(chunk).await;
			}
			// Inspect at most one record plus CRLF before accepting more input.
			let available = chunk.len().min(self.max_record + 2 - self.line.len());
			let newline = chunk[..available].iter().position(|b| *b == b'\n');
			let end = newline.map_or(available, |i| i + 1);
			self.line.extend_from_slice(&chunk.split_to(end));
			if newline.is_some() {
				self.take_line(sink).await?;
			} else if self.line.len() > self.max_record + 1 {
				// Longer than a record plus a trailing `\r`.
				let line = std::mem::take(&mut self.line);
				self.overflow(line, sink).await?;
			}
		}
		Ok(())
	}

	async fn finish(&mut self, sink: &mut impl Sink) -> anyhow::Result<()> {
		if self.line.is_empty() {
			return Ok(());
		}
		self.take_line(sink).await
	}

	/// Handles the buffered line, including its newline if it has one.
	async fn take_line(&mut self, sink: &mut impl Sink) -> anyhow::Result<()> {
		let line = std::mem::take(&mut self.line);
		let content = line.strip_suffix(b"\n").unwrap_or(&line);
		let content = content.strip_suffix(b"\r").unwrap_or(content);
		if content.len() > self.max_record {
			return self.overflow(line, sink).await;
		}
		let content = trim_line(content);
		if content.is_empty() {
			return sink.raw(line.into()).await;
		}
		let record = parse_record(content);
		if !*self.batch.get_or_insert(record.is_some()) {
			return sink.raw(line.into()).await;
		}
		let Some((url, record)) = record else {
			anyhow::bail!("invalid batch record");
		};
		sink.record(url, record).await?;
		self.records += 1;
		Ok(())
	}

	/// Handles a line too long to be a record: rejected in batch input, passed through otherwise.
	async fn overflow(&mut self, line: Vec<u8>, sink: &mut impl Sink) -> anyhow::Result<()> {
		ensure!(self.batch != Some(true), RecordTooLarge);
		self.batch = Some(false);
		sink.raw(line.into()).await
	}
}

fn trim_line(line: &[u8]) -> &[u8] {
	let line = line.strip_prefix("\u{feff}".as_bytes()).unwrap_or(line);
	line.trim_ascii()
}

/// Parses a batch record: an object with a `url` and an object `body`.
fn parse_record(line: &[u8]) -> Option<(String, Map<String, Value>)> {
	let Ok(Value::Object(record)) = serde_json::from_slice(line) else {
		return None;
	};
	let url = record.get("url")?.as_str()?.to_owned();
	record.get("body")?.as_object()?;
	Some((url, record))
}

#[cfg(test)]
pub(in crate::llm::batch) mod tests {
	use super::*;

	/// A multipart body with boundary `x`. The `file` field is given a filename.
	pub(in crate::llm::batch) fn multipart_body(fields: &[(&str, &str)]) -> String {
		let mut body = String::new();
		for (name, value) in fields {
			let filename = if *name == "file" {
				"; filename=\"f\""
			} else {
				""
			};
			body.push_str(&format!(
				"--x\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\n\r\n{value}\r\n"
			));
		}
		body + "--x--\r\n"
	}

	pub(in crate::llm::batch) fn parse(body: String) -> multer::Multipart<'static> {
		// Split both multipart framing and JSON records across transport chunks.
		let chunks: Vec<_> = body
			.as_bytes()
			.chunks(7)
			.map(|chunk| Ok::<_, std::io::Error>(Bytes::copy_from_slice(chunk)))
			.collect();
		let stream = futures::stream::iter(chunks);
		multer::Multipart::new(stream, "x")
	}

	#[derive(Default)]
	struct Collect {
		raw: Vec<u8>,
		records: usize,
	}

	impl Sink for Collect {
		async fn raw(&mut self, bytes: Bytes) -> anyhow::Result<()> {
			self.raw.extend_from_slice(&bytes);
			Ok(())
		}

		async fn record(&mut self, _: String, _: Map<String, Value>) -> anyhow::Result<()> {
			self.records += 1;
			Ok(())
		}
	}

	/// Walks an upload with a 64 byte record limit.
	async fn walk_fields(fields: &[(&str, &str)], always_batch: bool) -> anyhow::Result<Collect> {
		let mut sink = Collect::default();
		walk(
			parse(multipart_body(fields)),
			"x",
			64,
			always_batch,
			&mut sink,
		)
		.await?;
		Ok(sink)
	}

	const RECORD: &str = r#"{"url":"/v1/x","body":{}}"#;

	#[tokio::test]
	async fn batch_files_are_strict() {
		let records = format!("{RECORD}\n{RECORD}");
		for fields in [
			[("purpose", "batch"), ("file", records.as_str())],
			[("file", records.as_str()), ("purpose", "batch")],
		] {
			assert_eq!(walk_fields(&fields, false).await.unwrap().records, 2);
		}
		let malformed = format!("{RECORD}\n{{not json}}");
		assert!(
			walk_fields(&[("purpose", "batch"), ("file", &malformed)], false)
				.await
				.is_err()
		);
		let oversized = format!(r#"{{"url":"/v1/x","body":{{"pad":"{}"}}}}"#, "y".repeat(64));
		let error = walk_fields(&[("purpose", "batch"), ("file", &oversized)], false)
			.await
			.err()
			.unwrap();
		assert!(error.is::<RecordTooLarge>());
	}

	#[tokio::test]
	async fn other_files_pass_through() {
		let pretty = "{\n  \"a\": 1\n}";
		let long = "x".repeat(100);
		for (file, purpose_first) in [(RECORD, true), (pretty, false), (long.as_str(), false)] {
			let fields = if purpose_first {
				[("purpose", "assistants"), ("file", file)]
			} else {
				[("file", file), ("purpose", "assistants")]
			};
			let walked = walk_fields(&fields, false).await.unwrap();
			assert_eq!(walked.records, 0);
			assert!(String::from_utf8_lossy(&walked.raw).contains(file));
		}
	}

	#[tokio::test]
	async fn other_files_keep_their_part_headers() {
		let body = "--x\r\ncontent-disposition: form-data; name=\"purpose\"\r\n\r\nassistants\r\n\
			--x\r\ncontent-disposition: form-data; name=\"file\"; filename*=UTF-8''r%C3%A9sum%C3%A9.txt\r\n\
			x-custom: 1\r\n\r\nhello\r\n--x--\r\n";
		let mut sink = Collect::default();
		walk(parse(body.to_owned()), "x", 64, false, &mut sink)
			.await
			.unwrap();
		assert_eq!(String::from_utf8(sink.raw).unwrap(), body);
	}

	#[tokio::test]
	async fn batch_purpose_must_match_the_file() {
		assert!(
			walk_fields(
				&[
					("purpose", "assistants"),
					("file", RECORD),
					("purpose", "batch")
				],
				false
			)
			.await
			.is_err()
		);
		// A late batch purpose rejects a file that was passed through.
		let file = format!("{{\n{RECORD}");
		assert!(
			walk_fields(&[("file", &file), ("purpose", "batch")], false)
				.await
				.is_err()
		);
		// When every file must be batch input, another purpose is rejected before the file.
		assert!(
			walk_fields(&[("purpose", "assistants"), ("file", RECORD)], true)
				.await
				.is_err()
		);
	}

	#[tokio::test]
	async fn oversized_transport_chunks() {
		let content = "x".repeat(1024);
		for batch in [Some(true), None] {
			let mut file = File {
				batch,
				line: Vec::new(),
				max_record: 64,
				bytes: 0,
				records: 0,
			};
			let mut sink = Collect::default();
			let result = file.chunk(Bytes::from(content.clone()), &mut sink).await;
			if batch == Some(true) {
				assert!(result.unwrap_err().is::<RecordTooLarge>());
				assert!(sink.raw.is_empty());
			} else {
				result.unwrap();
				file.finish(&mut sink).await.unwrap();
				assert_eq!(sink.raw, content.as_bytes());
			}
		}
	}
}
