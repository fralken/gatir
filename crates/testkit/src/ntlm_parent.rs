//! A parent proxy that demands NTLM authentication, for tests.
//!
//! Its side of the exchange is written from MS-NLMP independently of gatir's
//! client side: it derives the response it expects from the account's password
//! and compares, the way a domain controller would. A bug would have to be made
//! twice, in the same way, to go unnoticed.
//!
//! Authentication belongs to the connection, as in a real proxy: after a
//! request carrying an accepted AUTHENTICATE message, the connection serves
//! requests without further proof.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_PAD_INDIFFERENT};
use des::Des;
use des::cipher::BlockCipherEncrypt;
use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinHandle};

use crate::http::{Request, read_request};
use crate::origin::Reply;

const UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NTLM: u32 = 0x0000_0200;
const ALWAYS_SIGN: u32 = 0x0000_8000;
const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
const EXTENDED_SESSION_SECURITY: u32 = 0x0008_0000;
const TARGET_INFO: u32 = 0x0080_0000;
const VERSION: u32 = 0x0200_0000;
const KEY_128: u32 = 0x2000_0000;
const KEY_EXCH: u32 = 0x4000_0000;
const KEY_56: u32 = 0x8000_0000;

/// What the parent offers in its CHALLENGE message.
const SERVER_FLAGS: u32 = UNICODE
    | REQUEST_TARGET
    | NTLM
    | ALWAYS_SIGN
    | TARGET_TYPE_DOMAIN
    | EXTENDED_SESSION_SECURITY
    | TARGET_INFO
    | VERSION
    | KEY_128
    | KEY_EXCH
    | KEY_56;

/// The one account the parent knows.
#[derive(Debug, Clone)]
pub struct Account {
    pub user: String,
    pub domain: String,
    pub password: String,
}

impl Account {
    pub fn new(user: &str, domain: &str, password: &str) -> Self {
        Self {
            user: user.to_owned(),
            domain: domain.to_owned(),
            password: password.to_owned(),
        }
    }
}

/// How the parent behaves. The default is a well-behaved NTLM proxy.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `Proxy-Authenticate` fields of a `407` that is not an NTLM challenge.
    pub offers: Vec<String>,
    /// False makes the parent ignore NTLM messages, like one that only speaks
    /// the schemes in `offers`.
    pub ntlm: bool,
    /// Close the connection when the NEGOTIATE message arrives.
    pub close_on_negotiate: bool,
    /// Read the NEGOTIATE message and never answer it, keeping the connection open.
    pub stall_on_negotiate: bool,
    /// Send `Connection: close` with the `407` that carries the challenge.
    pub close_after_challenge: bool,
    /// Send `Connection: close` with every other `407`, and close the
    /// connection after it.
    pub close_after_refusal: bool,
    /// Forget a connection's authentication once it has served this many
    /// requests, so the next one is answered with a `407`.
    pub forget_after: Option<usize>,
    /// The server clock (a Windows FILETIME) to put in the target info.
    pub timestamp: Option<u64>,
    /// The Negotiate token that authenticates a connection. A request carrying
    /// `Proxy-Authorization: Negotiate` with exactly these bytes is served, and
    /// so is everything after it on that connection; any other token is refused.
    /// `None` refuses every Negotiate token.
    pub negotiate_token: Option<Vec<u8>>,
    /// A Negotiate exchange of two rounds, as when SPNEGO falls back to NTLM:
    /// the first token is answered with a `407` that carries a token of its
    /// own, and the second, on the same connection, authenticates it. Any
    /// other token is refused. Used instead of `negotiate_token`.
    pub negotiate_exchange: Option<NegotiateExchange>,
}

/// The three messages of a Negotiate exchange of two rounds.
#[derive(Debug, Clone)]
pub struct NegotiateExchange {
    /// What the client sends first.
    pub first: Vec<u8>,
    /// What the parent answers it with, in a `407`.
    pub challenge: Vec<u8>,
    /// What the client answers that with.
    pub second: Vec<u8>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            offers: vec!["NTLM".to_owned()],
            ntlm: true,
            close_on_negotiate: false,
            stall_on_negotiate: false,
            close_after_challenge: false,
            close_after_refusal: false,
            forget_after: None,
            timestamp: None,
            negotiate_token: None,
            negotiate_exchange: None,
        }
    }
}

/// A request as the parent saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub request: Request,
    /// The accepted connection that carried it, counting from 1.
    pub connection: usize,
    /// The type (1 or 3) of the NTLM message in `Proxy-Authorization`, if any.
    pub message: Option<u32>,
    /// The token of a `Proxy-Authorization: Negotiate` field, if any.
    pub negotiate: Option<Vec<u8>>,
    /// True if the handler answered it, false if it got a `407`.
    pub served: bool,
}

struct Shared {
    account: Account,
    options: Options,
    handler: Box<dyn Fn(&Request) -> Reply + Send + Sync>,
    seen: Mutex<Vec<Seen>>,
    connections: AtomicUsize,
    /// One per accepted connection, so dropping the parent closes them all.
    tasks: Mutex<Vec<AbortHandle>>,
}

/// Listens on a loopback port and answers like a proxy that wants NTLM.
/// Requests that pass authentication are answered by the handler.
pub struct MockNtlmParent {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl MockNtlmParent {
    pub async fn start<F>(account: Account, options: Options, handler: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind parent");
        let addr = listener.local_addr().expect("parent address");
        let shared = Arc::new(Shared {
            account,
            options,
            handler: Box::new(handler),
            seen: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
        });
        let task = tokio::spawn({
            let shared = shared.clone();
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let id = shared.connections.fetch_add(1, Ordering::SeqCst) + 1;
                    let connection = tokio::spawn(serve(stream, shared.clone(), id));
                    shared
                        .tasks
                        .lock()
                        .expect("tasks lock")
                        .push(connection.abort_handle());
                }
            }
        });
        Self { addr, shared, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every request received, in arrival order, including those answered `407`.
    pub fn requests(&self) -> Vec<Seen> {
        self.shared.seen.lock().expect("seen lock").clone()
    }

    /// The requests the handler answered.
    pub fn served(&self) -> Vec<Seen> {
        self.requests()
            .into_iter()
            .filter(|seen| seen.served)
            .collect()
    }

    /// Number of TCP connections accepted so far.
    pub fn connection_count(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }

    /// Number of NTLM messages of `kind` (1 = NEGOTIATE, 3 = AUTHENTICATE) received.
    pub fn messages(&self, kind: u32) -> usize {
        self.requests()
            .iter()
            .filter(|seen| seen.message == Some(kind))
            .count()
    }
}

/// Dropping the parent makes it disappear: it stops listening and closes every
/// connection it had open.
impl Drop for MockNtlmParent {
    fn drop(&mut self) {
        self.task.abort();
        for connection in self.shared.tasks.lock().expect("tasks lock").iter() {
            connection.abort();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Anonymous,
    /// The challenge sent, waiting for the answer.
    Challenged([u8; 8]),
    /// The first Negotiate token answered, waiting for the second.
    Continuing,
    Authenticated,
}

async fn serve(stream: TcpStream, shared: Arc<Shared>, id: usize) {
    let mut reader = BufReader::new(stream);
    let mut state = State::Anonymous;
    let mut served = 0usize;

    while let Ok(Some(request)) = read_request(&mut reader).await {
        let token = request
            .headers
            .get("proxy-authorization")
            .and_then(ntlm_token);
        let message = token.as_deref().and_then(message_type);
        let negotiate = request
            .headers
            .get("proxy-authorization")
            .and_then(negotiate_token);
        let record = |answered: bool| {
            shared.seen.lock().expect("seen lock").push(Seen {
                request: request.clone(),
                connection: id,
                message,
                negotiate: negotiate.clone(),
                served: answered,
            });
        };

        // A `407` to send instead of serving the request, and whether to close.
        let refusal: Option<(Vec<u8>, bool)> = if let (Some(proof), Some(exchange)) =
            (&negotiate, &shared.options.negotiate_exchange)
        {
            if *proof == exchange.first {
                state = State::Continuing;
                let field = format!("Negotiate {}", STANDARD.encode(&exchange.challenge));
                Some((reply_407(&[field], false), false))
            } else if *proof == exchange.second && state == State::Continuing {
                state = State::Authenticated;
                None
            } else {
                state = State::Anonymous;
                Some(shared.refusal())
            }
        } else if let Some(proof) = &negotiate {
            if shared.options.negotiate_token.as_ref() == Some(proof) {
                state = State::Authenticated;
                None
            } else {
                state = State::Anonymous;
                Some(shared.refusal())
            }
        } else if !shared.options.ntlm {
            if state == State::Authenticated {
                None
            } else {
                Some(shared.refusal())
            }
        } else {
            match (message, &token) {
                (Some(1), _) => {
                    if shared.options.close_on_negotiate {
                        record(false);
                        return;
                    }
                    if shared.options.stall_on_negotiate {
                        record(false);
                        std::future::pending::<()>().await;
                    }
                    let challenge = challenge_for(id);
                    state = State::Challenged(challenge);
                    Some((
                        shared.challenge_reply(challenge),
                        shared.options.close_after_challenge,
                    ))
                }
                (Some(3), Some(token)) => match state {
                    State::Challenged(challenge) if shared.accepts(token, &challenge) => {
                        state = State::Authenticated;
                        None
                    }
                    _ => {
                        state = State::Anonymous;
                        Some(shared.refusal())
                    }
                },
                _ if state == State::Authenticated => None,
                _ => Some(shared.refusal()),
            }
        };

        if let Some((bytes, close)) = refusal {
            record(false);
            let stream = reader.get_mut();
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
            if close {
                let _ = stream.shutdown().await;
                return;
            }
            continue;
        }

        record(true);
        served += 1;
        let reply = (shared.handler)(&request);
        if !reply.delay.is_zero() {
            tokio::time::sleep(reply.delay).await;
        }
        let stream = reader.get_mut();
        if stream.write_all(&reply.bytes).await.is_err() {
            return;
        }
        if reply.close {
            let _ = stream.shutdown().await;
            return;
        }
        if reply.echo {
            echo(&mut reader).await;
            return;
        }
        if shared
            .options
            .forget_after
            .is_some_and(|limit| served >= limit)
        {
            state = State::Anonymous;
            served = 0;
        }
    }
}

/// Sends back what the peer sends until it closes.
async fn echo(reader: &mut BufReader<TcpStream>) {
    let mut buffer = [0u8; 4096];
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        if reader.get_mut().write_all(&buffer[..count]).await.is_err() {
            return;
        }
    }
}

/// A different challenge for every connection, so a proof made for one is
/// useless on another.
pub(crate) fn challenge_for(connection: usize) -> [u8; 8] {
    let mut challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    challenge[0] = connection as u8;
    challenge
}

/// The bytes of an `NTLM <base64>` field value.
pub(crate) fn ntlm_token(value: &str) -> Option<Vec<u8>> {
    let (scheme, token) = value.trim().split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("NTLM") {
        return None;
    }
    STANDARD_PAD_INDIFFERENT.decode(token.trim()).ok()
}

/// The bytes of a `Negotiate <base64>` field value.
fn negotiate_token(value: &str) -> Option<Vec<u8>> {
    let (scheme, token) = value.trim().split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("Negotiate") {
        return None;
    }
    STANDARD_PAD_INDIFFERENT.decode(token.trim()).ok()
}

pub(crate) fn message_type(message: &[u8]) -> Option<u32> {
    if message.len() < 12 || &message[..8] != b"NTLMSSP\0" {
        return None;
    }
    Some(u32::from_le_bytes(message[8..12].try_into().ok()?))
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

impl Shared {
    /// A `407` that is not a challenge, and whether to close after it.
    fn refusal(&self) -> (Vec<u8>, bool) {
        let close = self.options.close_after_refusal;
        (reply_407(&self.options.offers, close), close)
    }

    fn challenge_reply(&self, challenge: [u8; 8]) -> Vec<u8> {
        let message = challenge_for_account(&self.account, &challenge, self.options.timestamp);
        let field = format!("NTLM {}", STANDARD.encode(message));
        reply_407(&[field], self.options.close_after_challenge)
    }

    /// Whether `message` is an AUTHENTICATE message answering `challenge`.
    fn accepts(&self, message: &[u8], challenge: &[u8; 8]) -> bool {
        accepts(&self.account, message, challenge, self.options.timestamp)
    }
}

/// The AV pairs of a CHALLENGE message for `account`, which a client must copy
/// into its NTLMv2 blob unchanged.
pub(crate) fn target_info(account: &Account, timestamp: Option<u64>) -> Vec<u8> {
    let mut info = Vec::new();
    av_pair(&mut info, 2, &utf16(&account.domain.to_uppercase()));
    av_pair(&mut info, 1, &utf16("PROXY"));
    av_pair(&mut info, 4, &utf16("corp.example.com"));
    av_pair(&mut info, 3, &utf16("proxy.corp.example.com"));
    if let Some(time) = timestamp {
        av_pair(&mut info, 7, &time.to_le_bytes());
    }
    av_pair(&mut info, 0, &[]);
    info
}

/// The CHALLENGE message (just the NTLM bytes, with no header around them)
/// that answers `account`'s server would send for `challenge`.
pub(crate) fn challenge_for_account(
    account: &Account,
    challenge: &[u8; 8],
    timestamp: Option<u64>,
) -> Vec<u8> {
    challenge_message(
        challenge,
        &account.domain.to_uppercase(),
        &target_info(account, timestamp),
    )
}

/// Whether `message` is an AUTHENTICATE message proving knowledge of
/// `account`'s password, answering `challenge`. `timestamp`, when the
/// CHALLENGE carried one, must be the same value passed to it.
pub(crate) fn accepts(
    account: &Account,
    message: &[u8],
    challenge: &[u8; 8],
    timestamp: Option<u64>,
) -> bool {
    let Some(auth) = Authenticate::parse(message) else {
        return false;
    };
    let unicode = auth.flags & UNICODE != 0;
    let (user, domain) = (
        auth.text(auth.user, unicode),
        auth.text(auth.domain, unicode),
    );
    if !user.eq_ignore_ascii_case(&account.user) || !domain.eq_ignore_ascii_case(&account.domain) {
        return false;
    }
    if !valid_response(&auth, &user, &domain, &account.password, challenge) {
        return false;
    }
    // An NTLMv2 blob must carry the target info the server sent, and its
    // clock when it sent one.
    if auth.nt.len() > 24 {
        let blob = &auth.nt[16..];
        let info = target_info(account, timestamp);
        if blob.len() < 32 || blob[28..blob.len() - 4] != info[..] {
            return false;
        }
        if let Some(time) = timestamp {
            return blob[8..16] == time.to_le_bytes();
        }
    }
    true
}

/// The cryptographic check of an AUTHENTICATE message: does its response
/// prove knowledge of `password`, given the `challenge` that was sent?
fn valid_response(
    auth: &Authenticate<'_>,
    user: &str,
    domain: &str,
    password: &str,
    challenge: &[u8; 8],
) -> bool {
    let nt_hash: [u8; 16] = Md4::digest(utf16(password)).into();
    match auth.nt.len() {
        24 => {
            // With extended session security the response is over the first
            // 8 bytes of MD5(challenge, client nonce), the nonce being the
            // start of the LM field.
            let challenge = if auth.flags & EXTENDED_SESSION_SECURITY != 0 && auth.lm.len() >= 8 {
                let mut md5 = Md5::new();
                md5.update(challenge);
                md5.update(&auth.lm[..8]);
                let mut session = [0u8; 8];
                session.copy_from_slice(&md5.finalize()[..8]);
                session
            } else {
                *challenge
            };
            auth.nt == desl(&nt_hash, &challenge)
        }
        length if length > 24 => {
            let key = hmac_md5(
                &nt_hash,
                &[&utf16(&format!("{}{domain}", user.to_uppercase()))],
            );
            let (proof, blob) = auth.nt.split_at(16);
            let nt_ok = blob.len() >= 32
                && blob[0] == 1
                && blob[1] == 1
                && proof == hmac_md5(&key, &[challenge, blob]);
            // LMv2: HMAC-MD5 over both challenges, then the client nonce.
            let lm_ok = auth.lm.len() == 24
                && auth.lm[..16] == hmac_md5(&key, &[challenge, &auth.lm[16..]]);
            nt_ok && lm_ok
        }
        _ => false,
    }
}

/// The fields of an AUTHENTICATE message (MS-NLMP 2.2.1.3) that matter here.
struct Authenticate<'a> {
    lm: &'a [u8],
    nt: &'a [u8],
    domain: &'a [u8],
    user: &'a [u8],
    flags: u32,
}

impl<'a> Authenticate<'a> {
    fn parse(message: &'a [u8]) -> Option<Self> {
        if message_type(message)? != 3 || message.len() < 64 {
            return None;
        }
        Some(Self {
            lm: field(message, 12)?,
            nt: field(message, 20)?,
            domain: field(message, 28)?,
            user: field(message, 36)?,
            flags: u32::from_le_bytes(message[60..64].try_into().ok()?),
        })
    }

    fn text(&self, bytes: &[u8], unicode: bool) -> String {
        if unicode {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
}

/// The bytes a security buffer at `position` points to.
fn field(message: &[u8], position: usize) -> Option<&[u8]> {
    let length = usize::from(u16::from_le_bytes(
        message.get(position..position + 2)?.try_into().ok()?,
    ));
    let offset = u32::from_le_bytes(message.get(position + 4..position + 8)?.try_into().ok()?);
    message.get(offset as usize..offset as usize + length)
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// DESL (MS-NLMP 6): three DES encryptions of `data`, keyed with consecutive
/// 7-byte slices of the hash padded with zeros to 21 bytes.
fn desl(hash: &[u8; 16], data: &[u8; 8]) -> Vec<u8> {
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(hash);
    let mut out = Vec::with_capacity(24);
    for slice in padded.chunks(7) {
        let cipher = Des::new_from_slice(&des_key(slice)).expect("a DES key is 8 bytes");
        let mut block = des::cipher::Block::<Des>::from(*data);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

/// 7 bytes to a DES key: 8 groups of 7 bits, each left-aligned in a byte. DES
/// ignores the parity bit, so it is left clear.
fn des_key(k: &[u8]) -> [u8; 8] {
    [
        k[0] >> 1,
        ((k[0] & 0x01) << 6) | (k[1] >> 2),
        ((k[1] & 0x03) << 5) | (k[2] >> 3),
        ((k[2] & 0x07) << 4) | (k[3] >> 4),
        ((k[3] & 0x0f) << 3) | (k[4] >> 5),
        ((k[4] & 0x1f) << 2) | (k[5] >> 6),
        ((k[5] & 0x3f) << 1) | (k[6] >> 7),
        k[6] & 0x7f,
    ]
    .map(|group| group << 1)
}

fn av_pair(info: &mut Vec<u8>, id: u16, value: &[u8]) {
    info.extend_from_slice(&id.to_le_bytes());
    info.extend_from_slice(&(value.len() as u16).to_le_bytes());
    info.extend_from_slice(value);
}

fn security_buffer(message: &mut Vec<u8>, length: usize, offset: usize) {
    message.extend_from_slice(&(length as u16).to_le_bytes());
    message.extend_from_slice(&(length as u16).to_le_bytes());
    message.extend_from_slice(&(offset as u32).to_le_bytes());
}

/// A CHALLENGE message (MS-NLMP 2.2.1.2) with a version field.
fn challenge_message(challenge: &[u8; 8], target_name: &str, target_info: &[u8]) -> Vec<u8> {
    const HEADER: usize = 56;
    let name = utf16(target_name);

    let mut message = Vec::new();
    message.extend_from_slice(b"NTLMSSP\0");
    message.extend_from_slice(&2u32.to_le_bytes());
    security_buffer(&mut message, name.len(), HEADER);
    message.extend_from_slice(&SERVER_FLAGS.to_le_bytes());
    message.extend_from_slice(challenge);
    message.extend_from_slice(&[0; 8]);
    security_buffer(&mut message, target_info.len(), HEADER + name.len());
    message.extend_from_slice(&[6, 0, 0x70, 0x17, 0, 0, 0, 0x0f]);
    message.extend_from_slice(&name);
    message.extend_from_slice(target_info);
    message
}

/// A `407` with one `Proxy-Authenticate` field per entry of `fields`.
fn reply_407(fields: &[String], close: bool) -> Vec<u8> {
    const BODY: &str = "Proxy authentication required\n";
    let mut head = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
    for field in fields {
        head.push_str(&format!("Proxy-Authenticate: {field}\r\n"));
    }
    head.push_str("Content-Type: text/plain\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", BODY.len()));
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    head.push_str(BODY);
    head.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server challenge of every example in MS-NLMP 4.2.
    const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    /// The AUTHENTICATE messages printed in MS-NLMP 4.2.2.3, 4.2.3.3 and
    /// 4.2.4.3, for User, Domain and Password.
    const NTLMV1: &str = concat!(
        "4e544c4d5353500003000000180018006c00000018001800840000000c000c00",
        "480000000800080054000000100010005c000000100010009c000000358280e2",
        "0501280a0000000f44006f006d00610069006e00550073006500720043004f00",
        "4d005000550054004500520098def7b87f88aa5dafe2df779688a172def11c7d",
        "5ccdef1367c43011f30298a2ad35ece64f16331c44bdbed927841f94518822b1",
        "b3f350c8958682ecbb3e3cb7",
    );
    const NTLM2_SESSION: &str = concat!(
        "4e544c4d5353500003000000180018006c00000018001800840000000c000c00",
        "480000000800080054000000100010005c000000000000009c00000035820882",
        "0501280a0000000f44006f006d00610069006e00550073006500720043004f00",
        "4d0050005500540045005200aaaaaaaaaaaaaaaa000000000000000000000000",
        "000000007537f803ae367128ca458204bde7caf81e97ed2683267232",
    );
    const NTLMV2: &str = concat!(
        "4e544c4d5353500003000000180018006c00000054005400840000000c000c00",
        "480000000800080054000000100010005c00000010001000d8000000358288e2",
        "0501280a0000000f44006f006d00610069006e00550073006500720043004f00",
        "4d005000550054004500520086c35097ac9cec102554764a57cccc19aaaaaaaa",
        "aaaaaaaa68cd0ab851e51c96aabc927bebef6a1c010100000000000000000000",
        "00000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e00",
        "01000c005300650072007600650072000000000000000000c5dad2544fc97990",
        "94ce1ce90bc9d03e",
    );

    fn valid(message: &str, password: &str, challenge: &[u8; 8]) -> bool {
        let bytes = hex::decode(message).unwrap();
        let auth = Authenticate::parse(&bytes).expect("a well-formed message");
        let unicode = auth.flags & UNICODE != 0;
        let user = auth.text(auth.user, unicode);
        let domain = auth.text(auth.domain, unicode);
        valid_response(&auth, &user, &domain, password, challenge)
    }

    #[test]
    fn accepts_the_authenticate_messages_printed_in_the_specification() {
        for (name, message) in [
            ("NTLMv1", NTLMV1),
            ("NTLM2 session", NTLM2_SESSION),
            ("NTLMv2", NTLMV2),
        ] {
            assert!(valid(message, "Password", &SERVER_CHALLENGE), "{name}");
        }
    }

    #[test]
    fn rejects_them_for_another_password_or_challenge() {
        let mut other = SERVER_CHALLENGE;
        other[7] ^= 1;
        for (name, message) in [
            ("NTLMv1", NTLMV1),
            ("NTLM2 session", NTLM2_SESSION),
            ("NTLMv2", NTLMV2),
        ] {
            assert!(!valid(message, "password", &SERVER_CHALLENGE), "{name}");
            assert!(!valid(message, "Password", &other), "{name}");
        }
    }

    #[test]
    fn reads_the_names_out_of_a_message() {
        let bytes = hex::decode(NTLMV2).unwrap();
        let auth = Authenticate::parse(&bytes).unwrap();
        assert_eq!(auth.text(auth.user, true), "User");
        assert_eq!(auth.text(auth.domain, true), "Domain");
    }

    #[test]
    fn messages_that_are_not_authenticate_messages_are_refused() {
        assert!(Authenticate::parse(&[]).is_none());
        assert!(Authenticate::parse(b"NTLMSSP\0\x01\0\0\0").is_none());
        let mut truncated = hex::decode(NTLMV2).unwrap();
        truncated.truncate(100);
        assert!(Authenticate::parse(&truncated).is_none());
    }
}
