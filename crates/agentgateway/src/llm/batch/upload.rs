use anyhow::{Context, ensure};
use bytes::Bytes;
use serde_json::{Map, Value};

use crate::http::{Body, HeaderMap};

/// Receives the records of a batch input file as it is walked.
pub(super) trait Sink {
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

/// Reads a multipart request body.
pub(super) fn multipart(
	headers: &HeaderMap,
	body: Body,
) -> anyhow::Result<multer::Multipart<'static>> {
	let content_type = headers
		.get(::http::header::CONTENT_TYPE)
		.context("missing content-type")?
		.to_str()?;
	let boundary = multer::parse_boundary(content_type)?;
	let stream = http_body_util::BodyExt::into_data_stream(body);
	Ok(multer::Multipart::new(stream, boundary))
}

/// Walks a multipart upload of batch input, splitting the file into records.
pub(super) async fn walk(
	mut multipart: multer::Multipart<'static>,
	max_record: usize,
	sink: &mut impl Sink,
) -> anyhow::Result<Summary> {
	let mut purpose: Option<bool> = None;
	let mut filename = None;
	let mut file_bytes = 0;
	let mut records = 0;
	while let Some(mut field) = multipart.next_field().await? {
		let name = field
			.name()
			.context("upload fields must be named")?
			.to_owned();
		match name.as_str() {
			"file" => {
				ensure!(filename.is_none(), "only one file is supported");
				ensure!(purpose != Some(false), "purpose must be batch");
				filename = Some(field.file_name().unwrap_or("input.jsonl").to_owned());
				let mut file = File {
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
			},
			"purpose" => {
				ensure!(purpose.is_none(), "only one purpose is supported");
				// Only enough of the value is kept to tell whether it is exactly "batch".
				let limit = b"batch".len() + 1;
				let mut value = Vec::new();
				while let Some(chunk) = field.chunk().await? {
					let keep = chunk.len().min(limit.saturating_sub(value.len()));
					value.extend_from_slice(&chunk[..keep]);
				}
				purpose = Some(value == b"batch");
			},
			_ => {},
		}
	}
	Ok(Summary {
		batch: purpose == Some(true),
		filename,
		file_bytes,
		records,
	})
}

struct File {
	line: Vec<u8>,
	max_record: usize,
	bytes: usize,
	records: usize,
}

impl File {
	async fn chunk(&mut self, mut chunk: Bytes, sink: &mut impl Sink) -> anyhow::Result<()> {
		self.bytes += chunk.len();
		while !chunk.is_empty() {
			// Inspect at most one record plus CRLF before accepting more input.
			let available = chunk.len().min(self.max_record + 2 - self.line.len());
			let newline = chunk[..available].iter().position(|b| *b == b'\n');
			let end = newline.map_or(available, |i| i + 1);
			self.line.extend_from_slice(&chunk.split_to(end));
			if newline.is_some() {
				self.take_line(sink).await?;
			} else {
				// Longer than a record plus a trailing `\r`.
				ensure!(self.line.len() <= self.max_record + 1, RecordTooLarge);
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
		ensure!(content.len() <= self.max_record, RecordTooLarge);
		let content = trim_line(content);
		if content.is_empty() {
			return Ok(());
		}
		let (url, record) = parse_record(content).context("invalid batch record")?;
		sink.record(url, record).await?;
		self.records += 1;
		Ok(())
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
		records: usize,
	}

	impl Sink for Collect {
		async fn record(&mut self, _: String, _: Map<String, Value>) -> anyhow::Result<()> {
			self.records += 1;
			Ok(())
		}
	}

	/// Walks an upload with a 64 byte record limit.
	async fn walk_fields(fields: &[(&str, &str)]) -> anyhow::Result<Summary> {
		walk(parse(multipart_body(fields)), 64, &mut Collect::default()).await
	}

	const RECORD: &str = r#"{"url":"/v1/x","body":{}}"#;

	#[tokio::test]
	async fn batch_files_are_strict() {
		let records = format!("{RECORD}\n{RECORD}");
		for fields in [
			[("purpose", "batch"), ("file", records.as_str())],
			[("file", records.as_str()), ("purpose", "batch")],
		] {
			let summary = walk_fields(&fields).await.unwrap();
			assert_eq!(summary.records, 2);
			assert!(summary.batch);
		}
		let malformed = format!("{RECORD}\n{{not json}}");
		assert!(
			walk_fields(&[("purpose", "batch"), ("file", &malformed)])
				.await
				.is_err()
		);
		let oversized = format!(r#"{{"url":"/v1/x","body":{{"pad":"{}"}}}}"#, "y".repeat(64));
		let error = walk_fields(&[("purpose", "batch"), ("file", &oversized)])
			.await
			.err()
			.unwrap();
		assert!(error.is::<RecordTooLarge>());
	}

	#[tokio::test]
	async fn other_purposes_are_rejected() {
		assert!(
			walk_fields(&[("purpose", "assistants"), ("file", RECORD)])
				.await
				.is_err()
		);
		let late = walk_fields(&[("file", RECORD), ("purpose", "assistants")])
			.await
			.unwrap();
		assert!(!late.batch);
	}

	#[tokio::test]
	async fn oversized_transport_chunks() {
		let mut file = File {
			line: Vec::new(),
			max_record: 64,
			bytes: 0,
			records: 0,
		};
		let result = file
			.chunk(Bytes::from("x".repeat(1024)), &mut Collect::default())
			.await;
		assert!(result.unwrap_err().is::<RecordTooLarge>());
	}
}
