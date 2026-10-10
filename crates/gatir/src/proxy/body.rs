//! Response bodies and locally generated responses.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper::header::{CONNECTION, CONTENT_TYPE, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::oneshot;

/// The body type of every response the proxy sends to a client.
pub(super) type Body = UnsyncBoxBody<Bytes, hyper::Error>;

pub(super) fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// A plain-text error page. `close` asks the client not to reuse the
/// connection, which is the safe choice after a protocol violation.
pub(super) fn error_response(
    status: StatusCode,
    message: impl Into<String>,
    close: bool,
) -> Response<Body> {
    let mut text = message.into();
    text.push('\n');
    let mut response = Response::new(full(text));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if close {
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Tells when a request body has been handed over completely. The wait for a
/// response is timed from then on: a slow upload is not a slow response.
pub(super) struct Sent(Option<oneshot::Receiver<()>>);

impl Sent {
    /// For a request that has no body to send.
    pub(super) fn already() -> Self {
        Self(None)
    }

    /// Waits until the whole body has been sent. A body that is dropped
    /// counts as sent.
    async fn wait(&mut self) {
        if let Some(receiver) = self.0.as_mut() {
            let _ = receiver.await;
            self.0 = None;
        }
    }
}

/// Wraps `body` so that the returned [`Sent`] resolves once all of it has been
/// read by the connection that sends it.
pub(super) fn watch(body: Body) -> (Body, Sent) {
    if body.is_end_stream() {
        return (body, Sent::already());
    }
    let (sender, receiver) = oneshot::channel();
    let watched = OnEnd::new(body, move || {
        let _ = sender.send(());
    });
    (watched.boxed_unsync(), Sent(Some(receiver)))
}

/// A body that runs `done` once, when the whole of it has been read. If it
/// fails or is dropped first, `done` is dropped without running.
pub(super) struct OnEnd<B> {
    inner: B,
    done: Option<Box<dyn FnOnce() + Send>>,
}

impl<B> OnEnd<B> {
    pub(super) fn new(inner: B, done: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner,
            done: Some(Box::new(done)),
        }
    }
}

impl<B> HttpBody for OnEnd<B>
where
    B: HttpBody<Data = Bytes, Error = hyper::Error> + Unpin,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        match &poll {
            // A body with a known length is complete after its last frame, and
            // hyper may never poll it again.
            Poll::Ready(None) => self.finish(),
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => self.finish(),
            Poll::Ready(Some(Err(_))) => self.done = None,
            _ => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> OnEnd<B> {
    fn finish(&mut self) {
        if let Some(done) = self.done.take() {
            done();
        }
    }
}

/// Waits for `response`, giving up `limit` after the request has been sent.
/// `None` means it timed out.
pub(super) async fn response_within<T>(
    limit: Duration,
    sent: &mut Sent,
    response: impl Future<Output = T>,
) -> Option<T> {
    tokio::pin!(response);
    tokio::select! {
        result = &mut response => Some(result),
        () = async {
            sent.wait().await;
            tokio::time::sleep(limit).await;
        } => None,
    }
}

/// [`response_within`] for a request that has no body to send.
pub(super) async fn answer_within<T>(
    limit: Duration,
    response: impl Future<Output = T>,
) -> Option<T> {
    response_within(limit, &mut Sent::already(), response).await
}
