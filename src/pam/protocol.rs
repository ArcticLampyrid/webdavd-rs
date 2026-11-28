//! Framed binary RPC protocol between the PAM processes.
//!
//! The same protocol is used between the server and the broker, and between
//! the broker and a worker. It is modeled after JSON-RPC:
//!
//! - A [`RpcMessage::Request`] has an `id`. The peer sends exactly one
//!   [`RpcMessage::Response`] with the same `id`. A client can send more
//!   requests before the responses arrive (pipelining), and responses can
//!   come in a different order than the requests.
//! - A [`RpcMessage::Notification`] has no `id` and gets no response.
//!
//! A frame is a 4-byte big-endian payload length (up to `u32::MAX`), then
//! the payload. A payload is a 1-byte message kind, then the fields of the
//! message. An integer is big-endian. A string is a 4-byte big-endian
//! length, then UTF-8 bytes. A nested enum is a 1-byte tag, then its fields.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::PamError;

const KIND_REQUEST: u8 = 0x01;
const KIND_NOTIFICATION: u8 = 0x02;
const KIND_RESPONSE: u8 = 0x03;

const METHOD_PING: u8 = 0x01;
const METHOD_AUTH: u8 = 0x02;

const NOTIFY_CANCEL: u8 = 0x01;

const RESULT_PONG: u8 = 0x01;
const RESULT_AUTH_OK: u8 = 0x02;
const RESULT_REJECTED: u8 = 0x03;
const RESULT_UNAVAILABLE: u8 = 0x04;
const RESULT_CANCELLED: u8 = 0x05;

/// Bytes of payload that a read allocates before the data arrives.
const READ_CHUNK: usize = 64 * 1024;

/// Parameters of one PAM authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub service: String,
    pub user:    String,
    pub pass:    String,
    /// Remote host. Empty if not known.
    pub remip:   String,
}

// Never show the password, at any log level.
impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRequest")
            .field("service", &self.service)
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .field("remip", &self.remip)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Ping,
    Auth(AuthRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// The client no longer waits for request `id`. If the request did not
    /// start yet, the peer skips it and responds [`RpcResult::Cancelled`].
    Cancel { id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResult {
    Pong,
    /// PAM accepted the credentials. `user` is the user name after PAM
    /// (`PAM_USER`), which a PAM module can change.
    AuthOk {
        user: String,
    },
    /// PAM rejected the credentials or the account.
    Rejected(String),
    /// No result from PAM: a PAM backend, a worker, or the broker failed.
    Unavailable(String),
    /// The request was cancelled before it started.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcMessage {
    Request { id: u64, method: Method },
    Notification(Notification),
    Response { id: u64, result: RpcResult },
}

impl From<Result<String, PamError>> for RpcResult {
    fn from(result: Result<String, PamError>) -> Self {
        match result {
            Ok(user) => RpcResult::AuthOk { user },
            Err(PamError::Rejected(msg)) => RpcResult::Rejected(msg),
            Err(PamError::Unavailable(msg)) => RpcResult::Unavailable(msg),
        }
    }
}

impl RpcResult {
    /// The inverse of the `From` conversion. The other results (`Pong`,
    /// `Cancelled`) are errors.
    pub fn into_auth(self) -> Result<String, PamError> {
        match self {
            RpcResult::AuthOk { user } => Ok(user),
            RpcResult::Rejected(msg) => Err(PamError::Rejected(msg)),
            RpcResult::Unavailable(msg) => Err(PamError::Unavailable(msg)),
            result => Err(PamError::Unavailable(format!("unexpected result {:?}", result))),
        }
    }
}

/// The encoded message is larger than a frame can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTooLarge(pub usize);

impl fmt::Display for FrameTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message too large ({} bytes, maximum {})", self.0, u32::MAX)
    }
}

impl std::error::Error for FrameTooLarge {}

impl From<FrameTooLarge> for io::Error {
    fn from(e: FrameTooLarge) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

impl RpcMessage {
    /// Encodes the message as a complete frame.
    pub fn to_frame(&self) -> Result<Vec<u8>, FrameTooLarge> {
        let mut frame = vec![0; 4];
        self.encode(&mut frame);
        let header = frame_header(frame.len() - 4)?;
        frame[..4].copy_from_slice(&header);
        Ok(frame)
    }

    /// Encodes a response. If it does not fit in a frame, encodes an
    /// [`RpcResult::Unavailable`] response instead.
    pub fn response_frame(id: u64, result: RpcResult) -> Vec<u8> {
        RpcMessage::Response { id, result }
            .to_frame()
            .unwrap_or_else(|e| {
                let result = RpcResult::Unavailable(e.to_string());
                RpcMessage::Response { id, result }
                    .to_frame()
                    .expect("small frame")
            })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            RpcMessage::Request { id, method } => {
                out.push(KIND_REQUEST);
                out.extend_from_slice(&id.to_be_bytes());
                method.encode(out);
            },
            RpcMessage::Notification(notification) => {
                out.push(KIND_NOTIFICATION);
                notification.encode(out);
            },
            RpcMessage::Response { id, result } => {
                out.push(KIND_RESPONSE);
                out.extend_from_slice(&id.to_be_bytes());
                result.encode(out);
            },
        }
    }

    fn decode(payload: &mut Payload<'_>) -> io::Result<Self> {
        match payload.u8()? {
            KIND_REQUEST => {
                Ok(RpcMessage::Request {
                    id:     payload.u64()?,
                    method: Method::decode(payload)?,
                })
            },
            KIND_NOTIFICATION => Ok(RpcMessage::Notification(Notification::decode(payload)?)),
            KIND_RESPONSE => {
                Ok(RpcMessage::Response {
                    id:     payload.u64()?,
                    result: RpcResult::decode(payload)?,
                })
            },
            kind => Err(invalid_data(format!("unknown message kind {:#04x}", kind))),
        }
    }

    /// Decodes a complete payload. Trailing bytes are an error.
    fn from_payload(bytes: &[u8]) -> io::Result<Self> {
        let mut payload = Payload(bytes);
        let msg = Self::decode(&mut payload)?;
        if !payload.0.is_empty() {
            return Err(invalid_data("trailing bytes in frame"));
        }
        Ok(msg)
    }
}

impl Method {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Method::Ping => out.push(METHOD_PING),
            Method::Auth(req) => {
                out.push(METHOD_AUTH);
                [&req.service, &req.user, &req.pass, &req.remip]
                    .into_iter()
                    .for_each(|s| put_str(out, s));
            },
        }
    }

    fn decode(payload: &mut Payload<'_>) -> io::Result<Self> {
        match payload.u8()? {
            METHOD_PING => Ok(Method::Ping),
            METHOD_AUTH => {
                Ok(Method::Auth(AuthRequest {
                    service: payload.string()?,
                    user:    payload.string()?,
                    pass:    payload.string()?,
                    remip:   payload.string()?,
                }))
            },
            tag => Err(invalid_data(format!("unknown method {:#04x}", tag))),
        }
    }
}

impl Notification {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Notification::Cancel { id } => {
                out.push(NOTIFY_CANCEL);
                out.extend_from_slice(&id.to_be_bytes());
            },
        }
    }

    fn decode(payload: &mut Payload<'_>) -> io::Result<Self> {
        match payload.u8()? {
            NOTIFY_CANCEL => Ok(Notification::Cancel { id: payload.u64()? }),
            tag => Err(invalid_data(format!("unknown notification {:#04x}", tag))),
        }
    }
}

impl RpcResult {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            RpcResult::Pong => out.push(RESULT_PONG),
            RpcResult::AuthOk { user } => {
                out.push(RESULT_AUTH_OK);
                put_str(out, user);
            },
            RpcResult::Rejected(msg) => {
                out.push(RESULT_REJECTED);
                put_str(out, msg);
            },
            RpcResult::Unavailable(msg) => {
                out.push(RESULT_UNAVAILABLE);
                put_str(out, msg);
            },
            RpcResult::Cancelled => out.push(RESULT_CANCELLED),
        }
    }

    fn decode(payload: &mut Payload<'_>) -> io::Result<Self> {
        match payload.u8()? {
            RESULT_PONG => Ok(RpcResult::Pong),
            RESULT_AUTH_OK => {
                Ok(RpcResult::AuthOk {
                    user: payload.string()?,
                })
            },
            RESULT_REJECTED => Ok(RpcResult::Rejected(payload.string()?)),
            RESULT_UNAVAILABLE => Ok(RpcResult::Unavailable(payload.string()?)),
            RESULT_CANCELLED => Ok(RpcResult::Cancelled),
            tag => Err(invalid_data(format!("unknown result {:#04x}", tag))),
        }
    }
}

/// Cursor over the bytes of a payload.
struct Payload<'a>(&'a [u8]);

impl Payload<'_> {
    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        if n > self.0.len() {
            return Err(invalid_data("truncated frame"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn string(&mut self) -> io::Result<String> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        let bytes = self.take(len)?.to_vec();
        String::from_utf8(bytes).map_err(|_| invalid_data("invalid UTF-8 in string"))
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // If the length does not fit in a u32, the frame does not fit either, and
    // `to_frame` rejects it. Thus a wrong length is never sent.
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The frame header for a payload of `len` bytes.
fn frame_header(len: usize) -> Result<[u8; 4], FrameTooLarge> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| FrameTooLarge(len))
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Returns the payload length from the frame header. Returns `None` if the
/// input ended before the frame (`header` is empty).
fn payload_len(header: &[u8]) -> io::Result<Option<usize>> {
    match *header {
        [] => Ok(None),
        [a, b, c, d] => Ok(Some(u32::from_be_bytes([a, b, c, d]) as usize)),
        _ => Err(truncated()),
    }
}

/// Decodes a payload that must have `len` bytes. Fewer bytes mean that the
/// input ended in the payload.
fn decode_payload(payload: &[u8], len: usize) -> io::Result<RpcMessage> {
    if payload.len() != len {
        return Err(truncated());
    }
    RpcMessage::from_payload(payload)
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame")
}

/// Reads one message. Returns `None` if the input ends before the message.
/// If the input ends in a message, that is an error.
pub fn read(input: &mut impl Read) -> io::Result<Option<RpcMessage>> {
    let mut header = Vec::with_capacity(4);
    input.take(4).read_to_end(&mut header)?;
    let Some(len) = payload_len(&header)? else {
        return Ok(None);
    };
    // Allocate as the data arrives, not all of `len` in advance.
    let mut payload = Vec::with_capacity(len.min(READ_CHUNK));
    input.take(len as u64).read_to_end(&mut payload)?;
    decode_payload(&payload, len).map(Some)
}

/// Like [`read`], but asynchronous.
pub async fn read_async(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<RpcMessage>> {
    let mut header = Vec::with_capacity(4);
    input.take(4).read_to_end(&mut header).await?;
    let Some(len) = payload_len(&header)? else {
        return Ok(None);
    };
    let mut payload = Vec::with_capacity(len.min(READ_CHUNK));
    input.take(len as u64).read_to_end(&mut payload).await?;
    decode_payload(&payload, len).map(Some)
}

/// Sends one request to a peer that answers one request at a time, and reads
/// its response. Fails if the exchange takes longer than `limit`.
pub async fn call(
    output: &mut (impl AsyncWrite + Unpin),
    input: &mut (impl AsyncRead + Unpin),
    id: u64,
    method: Method,
    limit: Duration,
) -> io::Result<RpcResult> {
    let exchange = async {
        let frame = RpcMessage::Request { id, method }.to_frame()?;
        output.write_all(&frame).await?;
        output.flush().await?;
        match read_async(input).await? {
            Some(RpcMessage::Response { id: got, result }) if got == id => Ok(result),
            Some(msg) => Err(invalid_data(format!("expected response {}, got {:?}", id, msg))),
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end of output")),
        }
    };
    timeout(limit, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out"))?
}

/// Sends a `Ping` with `id` 0, and waits for the `Pong`.
pub async fn ping(
    output: &mut (impl AsyncWrite + Unpin),
    input: &mut (impl AsyncRead + Unpin),
    limit: Duration,
) -> io::Result<()> {
    match call(output, input, 0, Method::Ping, limit).await? {
        RpcResult::Pong => Ok(()),
        result => Err(invalid_data(format!("expected Pong, got {:?}", result))),
    }
}

/// Writes one frame.
pub fn write_frame(output: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    output.write_all(frame)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_request() -> AuthRequest {
        AuthRequest {
            service: "webdav".into(),
            user:    "alice".into(),
            pass:    "s3cr3t-pässword".into(),
            remip:   "192.0.2.1".into(),
        }
    }

    fn request(id: u64, method: Method) -> RpcMessage {
        RpcMessage::Request { id, method }
    }

    fn response(id: u64, result: RpcResult) -> RpcMessage {
        RpcMessage::Response { id, result }
    }

    fn roundtrip(msg: RpcMessage) {
        let frame = msg.to_frame().unwrap();
        for result in read_both(&frame) {
            assert_eq!(result.unwrap(), Some(msg.clone()));
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    fn read_err(bytes: &[u8]) -> io::Error {
        read(&mut &bytes[..]).unwrap_err()
    }

    #[test]
    fn roundtrip_all_messages() {
        let no_remip = AuthRequest {
            remip: String::new(),
            ..auth_request()
        };
        [
            request(0, Method::Ping),
            request(u64::MAX - 1, Method::Auth(auth_request())),
            request(2, Method::Auth(no_remip)),
            RpcMessage::Notification(Notification::Cancel { id: 42 }),
            response(7, RpcResult::Pong),
            response(
                8,
                RpcResult::AuthOk {
                    user: "alice-mapped".into(),
                },
            ),
            response(9, RpcResult::Rejected("Authentication failure".into())),
            response(10, RpcResult::Unavailable("timed out".into())),
            response(11, RpcResult::Cancelled),
        ]
        .into_iter()
        .for_each(roundtrip);
    }

    #[test]
    fn frame_header_limit() {
        assert_eq!(frame_header(0), Ok([0; 4]));
        assert_eq!(frame_header(u32::MAX as usize), Ok([0xff; 4]));
        let too_large = u32::MAX as usize + 1;
        assert_eq!(frame_header(too_large), Err(FrameTooLarge(too_large)));
        let err = io::Error::from(FrameTooLarge(too_large));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    fn read_both(bytes: &[u8]) -> [io::Result<Option<RpcMessage>>; 2] {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let asynchronous = rt.block_on(read_async(&mut &bytes[..]));
        [read(&mut &bytes[..]), asynchronous]
    }

    #[test]
    fn eof_and_truncated_frames() {
        for result in read_both(&[]) {
            assert_eq!(result.unwrap(), None);
        }
        let frame = request(1, Method::Auth(auth_request())).to_frame().unwrap();
        for len in 1..4 {
            for result in read_both(&frame[..len]) {
                assert_eq!(
                    result.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof,
                    "{} bytes",
                    len
                );
            }
        }
        for result in read_both(&frame[..frame.len() - 1]) {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
        // A huge length does not allocate the full payload in advance.
        for result in read_both(&u32::MAX.to_be_bytes()) {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[test]
    fn rejects_malformed_payloads() {
        let id = 1u64.to_be_bytes();
        let truncated_string = [
            &[KIND_REQUEST][..],
            &id,
            &[METHOD_AUTH],
            &10u32.to_be_bytes(),
            b"abc",
        ]
        .concat();
        let invalid_utf8 = [
            &[KIND_RESPONSE][..],
            &id,
            &[RESULT_REJECTED],
            &2u32.to_be_bytes(),
            &[0xff, 0xfe],
        ]
        .concat();
        let unknown_method = [&[KIND_REQUEST][..], &id, &[0x7f]].concat();
        let unknown_result = [&[KIND_RESPONSE][..], &id, &[0x7f]].concat();
        let trailing = [&[KIND_REQUEST][..], &id, &[METHOD_PING, 0]].concat();
        let malformed: [(&[u8], &str); 8] = [
            (&[], "empty payload"),
            (&[0x7f], "unknown kind"),
            (&[KIND_REQUEST, 0, 0, 1], "truncated id"),
            (&[KIND_NOTIFICATION, 0x7f], "unknown notification"),
            (&unknown_method, "unknown method"),
            (&unknown_result, "unknown result"),
            (&trailing, "trailing bytes"),
            (&truncated_string, "truncated string"),
        ];
        for (payload, what) in malformed {
            assert_eq!(
                read_err(&frame(payload)).kind(),
                io::ErrorKind::InvalidData,
                "{}",
                what
            );
        }
        assert_eq!(read_err(&frame(&invalid_utf8)).kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn debug_redacts_password() {
        let req = auth_request();
        let msg = request(1, Method::Auth(req.clone()));
        for text in [format!("{:?}", req), format!("{:#?}", msg)] {
            assert!(!text.contains(&req.pass), "password leaked: {}", text);
            assert!(text.contains("<redacted>"));
            assert!(text.contains(&req.user));
        }
    }
}
