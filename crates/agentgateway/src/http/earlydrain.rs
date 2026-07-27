use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use tokio::sync::Notify;

/// Per-request drain settings derived from the frontend `earlyResponseDrain` config.
/// Stored as a request extension. An unset `max_bytes` resolves to the request's
/// effective buffer limit when the body is wrapped.
#[derive(Debug, Clone)]
pub struct DrainConfig {
	pub max_bytes: Option<usize>,
	pub timeout: Duration,
}

/// How the request body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
	/// The body reached end-of-stream while proxying; no drain was needed.
	Passthrough,
	/// The drain read the remaining body to end-of-stream.
	Drained,
	/// The drain stopped at the byte bound.
	Truncated,
	/// The drain stopped on timeout, error, or because no runtime was available.
	Aborted,
}

#[derive(Debug)]
pub struct DrainState {
	/// The request body. Present while proxying; taken by `begin_drain` (takeover)
	/// or cleared when the body ends. The proxied sender sees end-of-stream once taken.
	body: Mutex<Option<crate::http::Body>>,
	outcome: Mutex<Option<DrainOutcome>>,
	notify: Notify,
	max_bytes: usize,
	timeout: Duration,
}

impl DrainState {
	fn finish(&self, outcome: DrainOutcome) {
		let mut o = self.outcome.lock();
		if o.is_none() {
			*o = Some(outcome);
		}
		drop(o);
		self.notify.notify_waiters();
	}

	pub fn is_finished(&self) -> bool {
		self.outcome.lock().is_some()
	}

	/// Marks the drain aborted if it has not finished. Used by callers that gave up
	/// waiting, so a later `is_finished` check cannot re-defer indefinitely.
	pub fn abandon(&self) {
		self.finish(DrainOutcome::Aborted);
	}

	/// Upper bound on how long a caller should wait for the drain; the drain task
	/// bounds itself by the configured timeout, this adds slack for scheduling.
	pub fn wait_budget(&self) -> Duration {
		self.timeout + Duration::from_secs(1)
	}

	pub async fn wait(&self) -> DrainOutcome {
		loop {
			let notified = self.notify.notified();
			if let Some(o) = *self.outcome.lock() {
				return o;
			}
			notified.await;
		}
	}

	/// Takes over the request body and drains it in a background task, bounded by the
	/// configured byte/time budget. The proxied sender observes end-of-stream on its
	/// next poll; remaining bytes are pulled through any capture layers beneath.
	/// No-op if the body already ended or a drain is running.
	pub fn begin_drain(self: &Arc<Self>) {
		if self.is_finished() {
			return;
		}
		let Some(body) = self.body.lock().take() else {
			// Body ended, or another drain already owns it.
			return;
		};
		let state = self.clone();
		let Ok(handle) = tokio::runtime::Handle::try_current() else {
			self.finish(DrainOutcome::Aborted);
			return;
		};
		handle.spawn(async move {
			let outcome = tokio::time::timeout(state.timeout, drain(body, state.max_bytes))
				.await
				.unwrap_or(DrainOutcome::Aborted);
			tracing::debug!(?outcome, "early response drain finished");
			state.finish(outcome);
		});
	}
}

/// Wraps the request body sent upstream so the body can be reclaimed and drained when
/// the upstream finishes responding without consuming it (see [`DrainState::begin_drain`]).
///
/// Must be the outermost body wrapper so the drain pulls bytes through any
/// capture/inspection layers (e.g. `RecordedBody`) beneath it.
#[derive(Debug)]
pub struct EarlyDrainBody {
	state: Arc<DrainState>,
}

impl EarlyDrainBody {
	/// Installs the wrapper on `req` when a `DrainConfig` extension is present and the
	/// request has a body. Returns the shared state used to trigger and await the drain.
	pub fn wrap(req: &mut crate::http::Request) -> Option<Arc<DrainState>> {
		let cfg = req.extensions().get::<DrainConfig>()?.clone();
		if req.headers().contains_key(::http::header::UPGRADE) {
			return None;
		}
		if req.body().is_end_stream() {
			return None;
		}
		// Default to the effective buffer limit, which also caps body capture.
		let max_bytes = cfg
			.max_bytes
			.unwrap_or_else(|| crate::http::buffer_limit(req));
		let body = std::mem::replace(req.body_mut(), crate::http::Body::empty());
		let (body, state) = Self::wrap_body(body, max_bytes, cfg.timeout);
		*req.body_mut() = crate::http::Body::new(body);
		Some(state)
	}

	fn wrap_body(
		body: crate::http::Body,
		max_bytes: usize,
		timeout: Duration,
	) -> (Self, Arc<DrainState>) {
		let state = Arc::new(DrainState {
			body: Mutex::new(Some(body)),
			outcome: Mutex::new(None),
			notify: Notify::new(),
			max_bytes,
			timeout,
		});
		(
			Self {
				state: state.clone(),
			},
			state,
		)
	}
}

impl Body for EarlyDrainBody {
	type Data = bytes::Bytes;
	type Error = crate::http::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.get_mut();
		let mut guard = this.state.body.lock();
		let Some(inner) = guard.as_mut() else {
			// Body ended earlier, or a drain took it over: the sender is done.
			return Poll::Ready(None);
		};
		let res = futures::ready!(Pin::new(inner).poll_frame(cx));
		match &res {
			None => {
				*guard = None;
				this.state.finish(DrainOutcome::Passthrough);
			},
			Some(Err(_)) => {
				*guard = None;
				this.state.finish(DrainOutcome::Aborted);
			},
			Some(Ok(f)) if f.is_trailers() => {
				*guard = None;
				this.state.finish(DrainOutcome::Passthrough);
			},
			Some(Ok(_)) => {},
		}
		Poll::Ready(res)
	}

	fn is_end_stream(&self) -> bool {
		self
			.state
			.body
			.lock()
			.as_ref()
			.is_none_or(|b| b.is_end_stream())
	}

	fn size_hint(&self) -> SizeHint {
		self
			.state
			.body
			.lock()
			.as_ref()
			.map(|b| b.size_hint())
			.unwrap_or_else(|| SizeHint::with_exact(0))
	}
}

impl Drop for EarlyDrainBody {
	fn drop(&mut self) {
		// Sender abandoned the body early (e.g. upstream died): drain what remains.
		self.state.begin_drain();
	}
}

async fn drain(mut body: crate::http::Body, limit: usize) -> DrainOutcome {
	let mut read = 0usize;
	loop {
		match body.frame().await {
			Some(Ok(f)) => {
				if let Some(d) = f.data_ref() {
					read += d.remaining();
					if read > limit {
						return DrainOutcome::Truncated;
					}
				}
			},
			Some(Err(_)) => return DrainOutcome::Aborted,
			None => return DrainOutcome::Drained,
		}
	}
}

#[cfg(test)]
mod tests {
	use bytes::Bytes;
	use http_body::Frame;
	use http_body_util::StreamBody;

	use super::*;

	fn mock_body(data: Vec<&'static [u8]>) -> crate::http::Body {
		let iter = data
			.into_iter()
			.map(|d| Ok::<_, crate::http::Error>(Frame::data(Bytes::from_static(d))));
		crate::http::Body::new(StreamBody::new(futures_util::stream::iter(iter)))
	}

	#[tokio::test]
	async fn takeover_drains_unread_body_through_capture() {
		// Upstream reads one frame then responds; the drain must pull the rest
		// through the capture tee and end the proxied body.
		let (recorded_body, handle) =
			crate::http::RecordedBody::new(mock_body(vec![b"part1", b"part2", b"part3"]));
		let (mut body, state) = EarlyDrainBody::wrap_body(
			crate::http::Body::new(recorded_body),
			usize::MAX,
			Duration::from_secs(5),
		);

		let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
		assert_eq!(first, Bytes::from_static(b"part1"));

		state.begin_drain();
		assert_eq!(state.wait().await, DrainOutcome::Drained);
		assert_eq!(handle.bytes(), Bytes::from_static(b"part1part2part3"));

		// The proxied sender now sees end-of-stream.
		assert!(body.frame().await.is_none());
	}

	#[tokio::test]
	async fn sender_dropping_body_triggers_drain() {
		let (recorded_body, handle) =
			crate::http::RecordedBody::new(mock_body(vec![b"part1", b"part2"]));
		let (mut body, state) = EarlyDrainBody::wrap_body(
			crate::http::Body::new(recorded_body),
			usize::MAX,
			Duration::from_secs(5),
		);
		let _ = body.frame().await;
		drop(body);
		assert_eq!(state.wait().await, DrainOutcome::Drained);
		assert_eq!(handle.bytes(), Bytes::from_static(b"part1part2"));
	}

	#[tokio::test]
	async fn drain_stops_at_byte_bound() {
		let (mut body, state) = EarlyDrainBody::wrap_body(
			mock_body(vec![b"part1", b"part2", b"part3"]),
			7,
			Duration::from_secs(5),
		);
		let _ = body.frame().await;
		state.begin_drain();
		assert_eq!(state.wait().await, DrainOutcome::Truncated);
	}

	#[tokio::test(start_paused = true)]
	async fn drain_gives_up_on_stalled_client() {
		let stalled = crate::http::Body::new(StreamBody::new(futures_util::stream::pending::<
			Result<Frame<Bytes>, crate::http::Error>,
		>()));
		let (body, state) = EarlyDrainBody::wrap_body(stalled, usize::MAX, Duration::from_secs(5));
		state.begin_drain();
		drop(body);
		assert_eq!(state.wait().await, DrainOutcome::Aborted);
	}

	#[tokio::test]
	async fn fully_proxied_body_needs_no_drain() {
		let (body, state) = EarlyDrainBody::wrap_body(
			mock_body(vec![b"all", b"read"]),
			usize::MAX,
			Duration::from_secs(5),
		);
		let collected = crate::http::Body::new(body).collect().await.unwrap();
		assert_eq!(collected.to_bytes(), Bytes::from_static(b"allread"));
		assert_eq!(state.wait().await, DrainOutcome::Passthrough);
	}
}
