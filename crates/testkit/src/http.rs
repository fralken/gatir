//! Minimal HTTP/1.1 reading and writing helpers.
//!
//! Written by hand on purpose: tests that exercise the proxy must not rely on
//! the same HTTP library the proxy uses.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Header fields in wire order; names are matched case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn push(&mut self, name: &str, value: &str) {
        self.0.push((name.to_owned(), value.to_owned()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Debug, Clone, Copy)]
enum BodyKind {
    None,
    Length(usize),
    Chunked,
    UntilClose,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn eof() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

fn is_chunked(headers: &Headers) -> bool {
    headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

fn content_length(headers: &Headers) -> io::Result<Option<usize>> {
    headers
        .get("content-length")
        .map(|value| value.parse().map_err(|_| invalid("bad Content-Length")))
        .transpose()
}

/// Reads the start line and header fields. `None` means a clean EOF before
/// any byte of a new message.
async fn read_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<(String, Headers)>> {
    let mut first = String::new();
    if reader.read_line(&mut first).await? == 0 {
        return Ok(None);
    }
    let first = first.trim_end_matches(['\r', '\n']).to_owned();

    let mut headers = Headers::default();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(eof());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(Some((first, headers)));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed header line"))?;
        headers.push(name.trim(), value.trim());
    }
}

async fn read_body<R: AsyncBufRead + Unpin>(reader: &mut R, kind: BodyKind) -> io::Result<Vec<u8>> {
    match kind {
        BodyKind::None => Ok(Vec::new()),
        BodyKind::Length(length) => {
            let mut body = vec![0; length];
            reader.read_exact(&mut body).await?;
            Ok(body)
        }
        BodyKind::UntilClose => {
            let mut body = Vec::new();
            reader.read_to_end(&mut body).await?;
            Ok(body)
        }
        BodyKind::Chunked => read_chunked(reader).await,
    }
}

async fn read_chunked<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(eof());
        }
        let size_text = line.trim().split(';').next().unwrap_or_default();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| invalid("bad chunk size"))?;
        if size == 0 {
            // Trailer section, ended by an empty line.
            loop {
                let mut trailer = String::new();
                if reader.read_line(&mut trailer).await? == 0 {
                    return Err(eof());
                }
                if trailer.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..]).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(invalid("missing CRLF after chunk data"));
        }
    }
}

/// Reads one request. `None` means the peer closed the connection cleanly.
pub async fn read_request<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Option<Request>> {
    let Some((line, headers)) = read_head(reader).await? else {
        return Ok(None);
    };
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("malformed request line"));
    };
    let kind = if is_chunked(&headers) {
        BodyKind::Chunked
    } else if let Some(length) = content_length(&headers)? {
        BodyKind::Length(length)
    } else {
        BodyKind::None
    };
    let body = read_body(reader, kind).await?;
    Ok(Some(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        body,
    }))
}

/// Reads one response. `head_request` must be true when answering a HEAD.
pub async fn read_response<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    head_request: bool,
) -> io::Result<Response> {
    let Some((line, headers)) = read_head(reader).await? else {
        return Err(eof());
    };
    let mut parts = line.splitn(3, ' ');
    let (Some(version), Some(status)) = (parts.next(), parts.next()) else {
        return Err(invalid("malformed status line"));
    };
    let status: u16 = status.parse().map_err(|_| invalid("bad status code"))?;
    let reason = parts.next().unwrap_or_default().to_owned();

    let kind = if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        BodyKind::None
    } else if is_chunked(&headers) {
        BodyKind::Chunked
    } else if let Some(length) = content_length(&headers)? {
        BodyKind::Length(length)
    } else {
        BodyKind::UntilClose
    };
    let body = read_body(reader, kind).await?;
    Ok(Response {
        version: version.to_owned(),
        status,
        reason,
        headers,
        body,
    })
}

/// A TCP client that speaks raw bytes, so tests control every byte sent.
pub struct RawClient {
    reader: BufReader<TcpStream>,
}

impl RawClient {
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(TcpStream::connect(addr).await?),
        })
    }

    pub async fn send(&mut self, data: impl AsRef<[u8]>) -> io::Result<()> {
        let stream = self.reader.get_mut();
        stream.write_all(data.as_ref()).await?;
        stream.flush().await
    }

    /// Reads one response, failing instead of hanging if none arrives.
    pub async fn read_response(&mut self, head_request: bool) -> io::Result<Response> {
        tokio::time::timeout(READ_TIMEOUT, read_response(&mut self.reader, head_request))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no response in time"))?
    }

    /// Reads everything until the peer closes the connection.
    pub async fn read_to_end(&mut self) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        tokio::time::timeout(READ_TIMEOUT, self.reader.read_to_end(&mut data))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection stayed open"))??;
        Ok(data)
    }

    /// Reads exactly `length` bytes.
    pub async fn read_exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut data = vec![0; length];
        tokio::time::timeout(READ_TIMEOUT, self.reader.read_exact(&mut data))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "not enough data"))??;
        Ok(data)
    }

    /// Half-closes the connection: no more bytes will be sent.
    pub async fn shutdown_write(&mut self) -> io::Result<()> {
        self.reader.get_mut().shutdown().await
    }

    /// True if the peer closed (or reset) the connection within `within`.
    /// Returns false if the connection stays open or more data arrives.
    pub async fn closed_within(&mut self, within: Duration) -> bool {
        match tokio::time::timeout(within, self.reader.fill_buf()).await {
            Ok(Ok(buffered)) => buffered.is_empty(),
            Ok(Err(_)) => true,
            Err(_) => false,
        }
    }
}
