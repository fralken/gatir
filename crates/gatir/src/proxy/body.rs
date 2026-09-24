//! Response bodies and locally generated responses.

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONNECTION, CONTENT_TYPE, HeaderValue};
use hyper::{Response, StatusCode};

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
