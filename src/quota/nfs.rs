//! NFS user quota through the `rquota` RPC service (`rpc.rquotad`).
//!
//! The server port comes from the portmapper (IPv4, `PMAPPROC_GETPORT`) or
//! rpcbind (IPv6, `RPCBPROC_GETADDR`). UDP is tried first, then TCP. All
//! requests share one deadline.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use onc_rpc::auth::{AuthFlavor, AuthUnixParams};
use onc_rpc::{AcceptedStatus, CallBody, MessageType, ReplyBody, RpcMessage};

use super::UserQuota;

/// Time limit for all RPC requests of one quota lookup.
const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MESSAGE_LEN: usize = 64 * 1024;
/// Most significant bit of the RPC record marking header.
const LAST_FRAGMENT: u32 = 1 << 31;

const RPCBIND_PORT: u16 = 111;
const PMAP_PROG: u32 = 100_000;
const PMAP_VERS: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const RPCB_VERS: u32 = 3;
const RPCBPROC_GETADDR: u32 = 3;

const RQUOTA_PROG: u32 = 100_011;
const RQUOTA_VERS: u32 = 1;
const EXT_RQUOTA_VERS: u32 = 2;
const RQUOTAPROC_GETQUOTA: u32 = 1;
const RQ_PATHLEN: usize = 1024;
const USRQUOTA: u32 = 0;

const Q_OK: u32 = 1;
const Q_NOQUOTA: u32 = 2;
const Q_EPERM: u32 = 3;

/// Get the quota of `uid` on the NFS mount `source` (`host:/path` or
/// `[ipv6]:/path`). `addr` is the server address from the mount options.
pub(super) fn user_quota(source: &str, fstype: &str, addr: Option<&str>, uid: u32) -> io::Result<UserQuota> {
    let (host, path) = split_source(source).ok_or_else(|| invalid_data("invalid NFS mount source"))?;
    let ip = resolve(addr.unwrap_or(host))?;
    let payload = query(ip, export_path(path, fstype), uid)?;
    decode_getquota_result(&payload)
}

/// Split an NFS mount source into host and remote path.
fn split_source(source: &str) -> Option<(&str, &str)> {
    let (host, path) = match source.strip_prefix('[') {
        Some(rest) => rest.split_once("]:")?,
        None => {
            let colon = source.find(":/")?;
            (&source[..colon], &source[colon + 1..])
        },
    };
    (!host.is_empty() && path.starts_with('/')).then_some((host, path))
}

/// NFSv4 servers expect the path relative to the pseudo root, without leading `/`.
fn export_path<'a>(path: &'a str, fstype: &str) -> &'a str {
    match fstype {
        "nfs4" => path.trim_start_matches('/'),
        _ => path,
    }
}

fn resolve(host: &str) -> io::Result<IpAddr> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    (host, 0)
        .to_socket_addrs()?
        .map(|addr| addr.ip())
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {}", host)))
}

/// Ask rquotad for the quota, over UDP then TCP, with protocol version 1 then 2.
/// Returns the `getquota_rslt` payload.
fn query(ip: IpAddr, path: &str, uid: u32) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + TIMEOUT;
    let requests = [
        (RQUOTA_VERS, encode_getquota_args(path, uid)?),
        (EXT_RQUOTA_VERS, encode_ext_getquota_args(path, uid)?),
    ];
    let mut last_err = io::Error::from(io::ErrorKind::Unsupported);
    for transport in [Transport::Udp, Transport::Tcp] {
        let client = RpcClient {
            ip,
            transport,
            deadline,
        };
        for (vers, args) in &requests {
            let result = client
                .getport(RQUOTA_PROG, *vers)
                .and_then(|port| client.call(port, RQUOTA_PROG, *vers, RQUOTAPROC_GETQUOTA, true, args));
            match result {
                Ok(payload) => return Ok(payload),
                // Another transport or version does not help when the deadline is reached.
                Err(err) if err.kind() == io::ErrorKind::TimedOut => return Err(err),
                Err(err) => last_err = err,
            }
        }
    }
    Err(last_err)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

struct RpcClient {
    ip:        IpAddr,
    transport: Transport,
    deadline:  Instant,
}

impl RpcClient {
    /// Look up the port of `prog`/`vers` for this transport.
    fn getport(&self, prog: u32, vers: u32) -> io::Result<u16> {
        let port = match self.ip {
            IpAddr::V4(_) => {
                let prot = match self.transport {
                    Transport::Udp => libc::IPPROTO_UDP as u32,
                    Transport::Tcp => libc::IPPROTO_TCP as u32,
                };
                let args = XdrWriter::default().u32(prog).u32(vers).u32(prot).u32(0).finish();
                let reply = self.call(RPCBIND_PORT, PMAP_PROG, PMAP_VERS, PMAPPROC_GETPORT, false, &args)?;
                u16::try_from(XdrReader::new(&reply).u32()?).ok()
            },
            IpAddr::V6(_) => {
                let netid = match self.transport {
                    Transport::Udp => "udp6",
                    Transport::Tcp => "tcp6",
                };
                let args = XdrWriter::default()
                    .u32(prog)
                    .u32(vers)
                    .string(netid.as_bytes())
                    .string(b"")
                    .string(b"")
                    .finish();
                let reply = self.call(RPCBIND_PORT, PMAP_PROG, RPCB_VERS, RPCBPROC_GETADDR, false, &args)?;
                let uaddr = XdrReader::new(&reply).string(RQ_PATHLEN)?;
                std::str::from_utf8(uaddr).ok().and_then(uaddr_port)
            },
        };
        port.filter(|&port| port != 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("RPC program {} version {} is not registered", prog, vers),
            )
        })
    }

    /// Make an RPC call and return the result payload.
    fn call(
        &self,
        port: u16,
        prog: u32,
        vers: u32,
        procedure: u32,
        auth: bool,
        args: &[u8],
    ) -> io::Result<Vec<u8>> {
        let xid = new_xid();
        let hostname = hostname();
        let credentials = if auth {
            AuthFlavor::AuthUnix(AuthUnixParams::new(
                xid,
                hostname.as_slice(),
                // SAFETY: geteuid and getegid cannot fail.
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                [],
            ))
        } else {
            AuthFlavor::AuthNone(None)
        };
        let body = CallBody::new(
            prog,
            vers,
            procedure,
            credentials,
            AuthFlavor::AuthNone(None),
            args,
        );
        let request = RpcMessage::new(xid, MessageType::Call(body)).serialise()?;

        let addr = SocketAddr::new(self.ip, port);
        let reply = match self.transport {
            Transport::Udp => self.exchange_udp(addr, xid, &request),
            Transport::Tcp => self.exchange_tcp(addr, &request),
        };
        reply.and_then(|reply| {
            reply_payload(xid, &reply)?.ok_or_else(|| invalid_data("RPC reply xid mismatch"))
        })
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "rquota request timed out"))
    }

    /// Send a request (with record marking header) as one datagram and wait for
    /// the reply with the same xid. Returns the reply with record marking header.
    fn exchange_udp(&self, addr: SocketAddr, xid: u32, request: &[u8]) -> io::Result<Vec<u8>> {
        let local: SocketAddr = match addr {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(addr)?;
        socket.send(&request[4..])?;
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        loop {
            socket.set_read_timeout(Some(self.remaining()?))?;
            let len = socket.recv(&mut buf).map_err(timeout_error)?;
            let reply = add_record_mark(&buf[..len]);
            // Ignore late replies to earlier requests.
            if reply_xid(&reply) == Some(xid) {
                return Ok(reply);
            }
        }
    }

    fn exchange_tcp(&self, addr: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&addr, self.remaining()?)?;
        stream.set_write_timeout(Some(self.remaining()?))?;
        stream.write_all(request)?;
        stream.set_read_timeout(Some(self.remaining()?))?;
        let mut reply = vec![0u8; 4];
        stream.read_exact(&mut reply).map_err(timeout_error)?;
        let len = onc_rpc::expected_message_len(&reply).map_err(invalid_data)? as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(invalid_data("RPC reply too large"));
        }
        reply.resize(len, 0);
        stream.read_exact(&mut reply[4..]).map_err(timeout_error)?;
        Ok(reply)
    }
}

fn add_record_mark(datagram: &[u8]) -> Vec<u8> {
    let header = (datagram.len() as u32) | LAST_FRAGMENT;
    header.to_be_bytes().iter().chain(datagram).copied().collect()
}

fn reply_xid(reply: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(reply.get(4..8)?.try_into().ok()?))
}

/// Decode an RPC reply (with record marking header). Returns `None` if the xid
/// does not match.
fn reply_payload(xid: u32, reply: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let msg = RpcMessage::try_from(reply).map_err(invalid_data)?;
    if msg.xid() != xid {
        return Ok(None);
    }
    match msg.reply_body() {
        Some(ReplyBody::Accepted(accepted)) => {
            match accepted.status() {
                AcceptedStatus::Success(payload) => Ok(Some(payload.to_vec())),
                AcceptedStatus::ProgramUnavailable |
                AcceptedStatus::ProgramMismatch { .. } |
                AcceptedStatus::ProcedureUnavailable => {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("RPC call not supported: {:?}", accepted.status()),
                    ))
                },
                status => Err(io::Error::other(format!("RPC call failed: {:?}", status))),
            }
        },
        Some(ReplyBody::Denied(rejected)) => {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("RPC call rejected: {:?}", rejected),
            ))
        },
        None => Err(invalid_data("RPC message is not a reply")),
    }
}

fn new_xid() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.subsec_nanos());
    nanos ^ std::process::id().rotate_left(16) ^ COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Host name for `AUTH_UNIX`, at most 255 bytes.
fn hostname() -> Vec<u8> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for `buf.len()` bytes.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return Vec::new();
    }
    buf.iter().copied().take_while(|&b| b != 0).take(255).collect()
}

/// Port from an rpcbind universal address (`h1.h2.h3.h4.p1.p2` or `ipv6.p1.p2`).
fn uaddr_port(uaddr: &str) -> Option<u16> {
    let mut parts = uaddr.rsplitn(3, '.');
    let low: u8 = parts.next()?.parse().ok()?;
    let high: u8 = parts.next()?.parse().ok()?;
    parts.next().filter(|host| !host.is_empty())?;
    Some(u16::from_be_bytes([high, low]))
}

fn encode_getquota_args(path: &str, uid: u32) -> io::Result<Vec<u8>> {
    Ok(XdrWriter::default().string(checked_path(path)?).u32(uid).finish())
}

fn encode_ext_getquota_args(path: &str, uid: u32) -> io::Result<Vec<u8>> {
    Ok(XdrWriter::default()
        .string(checked_path(path)?)
        .u32(USRQUOTA)
        .u32(uid)
        .finish())
}

fn checked_path(path: &str) -> io::Result<&[u8]> {
    if path.len() > RQ_PATHLEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NFS path too long"));
    }
    Ok(path.as_bytes())
}

/// Decode `getquota_rslt`.
fn decode_getquota_result(payload: &[u8]) -> io::Result<UserQuota> {
    let mut reader = XdrReader::new(payload);
    match reader.u32()? {
        Q_OK => Rquota::decode(&mut reader)?.user_quota(),
        Q_NOQUOTA => Err(io::Error::from_raw_os_error(libc::ESRCH)),
        Q_EPERM => Err(io::Error::from_raw_os_error(libc::EPERM)),
        status => Err(invalid_data(format!("unknown rquota status {}", status))),
    }
}

/// `struct rquota`. Times are not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rquota {
    bsize:      i32,
    active:     bool,
    bhardlimit: u32,
    bsoftlimit: u32,
    curblocks:  u32,
}

impl Rquota {
    fn decode(reader: &mut XdrReader<'_>) -> io::Result<Self> {
        let bsize = reader.u32()? as i32;
        let active = reader.u32()? != 0;
        let bhardlimit = reader.u32()?;
        let bsoftlimit = reader.u32()?;
        let curblocks = reader.u32()?;
        // fhardlimit, fsoftlimit, curfiles, btimeleft, ftimeleft
        (0..5).try_for_each(|_| reader.u32().map(drop))?;
        Ok(Rquota {
            bsize,
            active,
            bhardlimit,
            bsoftlimit,
            curblocks,
        })
    }

    fn user_quota(&self) -> io::Result<UserQuota> {
        let bsize = u64::try_from(self.bsize)
            .ok()
            .filter(|&bsize| bsize > 0)
            .ok_or_else(|| invalid_data(format!("invalid rquota block size {}", self.bsize)))?;
        // 0 and 0xffffffff both mean "no limit".
        let bytes = |blocks: u32| {
            match blocks {
                u32::MAX => 0,
                blocks => u64::from(blocks) * bsize,
            }
        };
        let used = u64::from(self.curblocks) * bsize;
        Ok(if self.active {
            UserQuota::new(used, bytes(self.bsoftlimit), bytes(self.bhardlimit))
        } else {
            UserQuota::new(used, 0, 0)
        })
    }
}

#[derive(Default)]
struct XdrWriter(Vec<u8>);

impl XdrWriter {
    fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn string(self, value: &[u8]) -> Self {
        let mut this = self.u32(value.len() as u32);
        this.0.extend_from_slice(value);
        this.0.resize(this.0.len().next_multiple_of(4), 0);
        this
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

struct XdrReader<'a>(&'a [u8]);

impl<'a> XdrReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        XdrReader(buf)
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated XDR data"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self, max_len: usize) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max_len {
            return Err(invalid_data("XDR string too long"));
        }
        let value = self.take(len)?;
        self.take(len.next_multiple_of(4) - len)?;
        Ok(value)
    }
}

fn invalid_data(err: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

/// Socket read timeouts are reported as `WouldBlock`.
fn timeout_error(err: io::Error) -> io::Error {
    match err.kind() {
        io::ErrorKind::WouldBlock => io::Error::new(io::ErrorKind::TimedOut, "rquota request timed out"),
        _ => err,
    }
}

#[cfg(test)]
mod tests {
    use onc_rpc::{AcceptedReply, RejectedReply};

    use super::*;

    fn rquota_payload(status: u32, rquota: Option<[u32; 10]>) -> Vec<u8> {
        rquota
            .into_iter()
            .flatten()
            .fold(XdrWriter::default().u32(status), XdrWriter::u32)
            .finish()
    }

    fn serialise_reply(xid: u32, body: ReplyBody<&[u8], &[u8]>) -> Vec<u8> {
        RpcMessage::new(xid, MessageType::Reply(body))
            .serialise()
            .unwrap()
    }

    #[test]
    fn split_nfs_source() {
        assert_eq!(
            split_source("server:/export/home"),
            Some(("server", "/export/home"))
        );
        assert_eq!(split_source("10.0.0.1:/"), Some(("10.0.0.1", "/")));
        assert_eq!(split_source("[::1]:/export"), Some(("::1", "/export")));
        assert_eq!(split_source("[fd00::1]:/"), Some(("fd00::1", "/")));
        assert_eq!(split_source("fd00::1:/export"), Some(("fd00::1", "/export")));
        assert_eq!(split_source("server:/a:/b"), Some(("server", "/a:/b")));
        assert_eq!(split_source("/dev/sda1"), None);
        assert_eq!(split_source(":/export"), None);
        assert_eq!(split_source("[::1]/export"), None);
        assert_eq!(split_source("[::1]:export"), None);
        assert_eq!(split_source("server:export"), None);
        assert_eq!(split_source(""), None);
    }

    #[test]
    fn nfs4_export_path() {
        assert_eq!(export_path("/export/home", "nfs"), "/export/home");
        assert_eq!(export_path("/export/home", "nfs4"), "export/home");
        assert_eq!(export_path("/", "nfs4"), "");
    }

    #[test]
    fn resolve_literal_addresses() {
        assert_eq!(resolve("192.0.2.1").unwrap(), IpAddr::from([192, 0, 2, 1]));
        assert_eq!(resolve("::1").unwrap(), IpAddr::from(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn universal_address_port() {
        assert_eq!(uaddr_port("192.0.2.1.3.233"), Some(1001));
        assert_eq!(uaddr_port("::1.2.255"), Some(767));
        assert_eq!(uaddr_port("fe80::1.0.111"), Some(111));
        assert_eq!(uaddr_port(""), None);
        assert_eq!(uaddr_port("1.2"), None);
        assert_eq!(uaddr_port("::1.256.0"), None);
    }

    #[test]
    fn encode_args() {
        let v1 = encode_getquota_args("/export", 1000).unwrap();
        assert_eq!(v1, b"\0\0\0\x07/export\0\0\0\x03\xe8");
        let v2 = encode_ext_getquota_args("/ab", 7).unwrap();
        assert_eq!(v2, b"\0\0\0\x03/ab\0\0\0\0\0\0\0\0\x07");
        let empty = encode_getquota_args("", 1).unwrap();
        assert_eq!(empty, b"\0\0\0\0\0\0\0\x01");
        assert!(encode_getquota_args(&"x".repeat(RQ_PATHLEN + 1), 1).is_err());
    }

    #[test]
    fn decode_quota() {
        // bsize, active, bhard, bsoft, curblocks, fhard, fsoft, curfiles, btime, ftime
        let payload = rquota_payload(Q_OK, Some([1024, 1, 200, 100, 50, 0, 0, 3, 0, 0]));
        assert_eq!(
            decode_getquota_result(&payload).unwrap(),
            UserQuota {
                used:  50 * 1024,
                limit: Some(100 * 1024),
            }
        );
        let payload = rquota_payload(Q_OK, Some([512, 1, 200, 0, 50, 0, 0, 0, 0, 0]));
        assert_eq!(decode_getquota_result(&payload).unwrap().limit, Some(200 * 512));
    }

    #[test]
    fn decode_unlimited_quota() {
        let unlimited = |rquota| decode_getquota_result(&rquota_payload(Q_OK, Some(rquota))).unwrap();
        assert_eq!(
            unlimited([1024, 1, 0, 0, 50, 0, 0, 0, 0, 0]),
            UserQuota {
                used:  50 * 1024,
                limit: None,
            }
        );
        assert_eq!(
            unlimited([1024, 1, u32::MAX, u32::MAX, 5, 0, 0, 0, 0, 0]).limit,
            None
        );
        assert_eq!(
            unlimited([1024, 1, 300, u32::MAX, 5, 0, 0, 0, 0, 0]).limit,
            Some(300 * 1024)
        );
        // Quota not active: limits are ignored.
        assert_eq!(unlimited([1024, 0, 200, 100, 5, 0, 0, 0, 0, 0]).limit, None);
    }

    #[test]
    fn decode_errors() {
        let errno = |payload: Vec<u8>| decode_getquota_result(&payload).unwrap_err().raw_os_error();
        assert_eq!(errno(rquota_payload(Q_NOQUOTA, None)), Some(libc::ESRCH));
        assert_eq!(errno(rquota_payload(Q_EPERM, None)), Some(libc::EPERM));
        let kind = |payload: Vec<u8>| decode_getquota_result(&payload).unwrap_err().kind();
        assert_eq!(kind(rquota_payload(9, None)), io::ErrorKind::InvalidData);
        assert_eq!(kind(rquota_payload(Q_OK, None)), io::ErrorKind::UnexpectedEof);
        assert_eq!(kind(vec![0, 0]), io::ErrorKind::UnexpectedEof);
        let bad_bsize = rquota_payload(Q_OK, Some([u32::MAX, 1, 1, 1, 1, 0, 0, 0, 0, 0]));
        assert_eq!(kind(bad_bsize), io::ErrorKind::InvalidData);
        let zero_bsize = rquota_payload(Q_OK, Some([0, 1, 1, 1, 1, 0, 0, 0, 0, 0]));
        assert_eq!(kind(zero_bsize), io::ErrorKind::InvalidData);
    }

    #[test]
    fn xdr_string_roundtrip() {
        let data = XdrWriter::default()
            .string(b"udp6")
            .string(b"abcde")
            .u32(7)
            .finish();
        assert_eq!(data.len(), 4 + 4 + 4 + 8 + 4);
        let mut reader = XdrReader::new(&data);
        assert_eq!(reader.string(16).unwrap(), b"udp6");
        assert_eq!(reader.string(16).unwrap(), b"abcde");
        assert_eq!(reader.u32().unwrap(), 7);
        assert!(XdrReader::new(&data).string(2).is_err());
        // Length larger than the data.
        assert!(XdrReader::new(b"\0\0\0\x09abc\0").string(16).is_err());
    }

    #[test]
    fn reply_decoding() {
        let payload = rquota_payload(Q_NOQUOTA, None);
        let accepted = |status| ReplyBody::Accepted(AcceptedReply::new(AuthFlavor::AuthNone(None), status));

        let reply = serialise_reply(42, accepted(AcceptedStatus::Success(payload.as_slice())));
        assert_eq!(reply_payload(42, &reply).unwrap(), Some(payload.clone()));
        assert_eq!(reply_payload(43, &reply).unwrap(), None);
        assert_eq!(reply_xid(&reply), Some(42));

        // Datagrams have no record marking header.
        assert_eq!(add_record_mark(&reply[4..]), reply);

        let reply = serialise_reply(1, accepted(AcceptedStatus::ProgramUnavailable));
        assert_eq!(
            reply_payload(1, &reply).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let reply = serialise_reply(1, accepted(AcceptedStatus::SystemError));
        assert_eq!(reply_payload(1, &reply).unwrap_err().kind(), io::ErrorKind::Other);

        let rejected = ReplyBody::Denied(RejectedReply::RpcVersionMismatch { low: 2, high: 2 });
        let reply = serialise_reply(1, rejected);
        assert_eq!(
            reply_payload(1, &reply).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        assert_eq!(
            reply_payload(1, b"\x80\0\0\x02xy").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            reply_payload(1, b"").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unreachable_server_times_out_or_fails() {
        // TEST-NET-1 is not routable: the lookup must fail within the deadline.
        let start = Instant::now();
        assert!(user_quota("192.0.2.1:/export", "nfs", None, 1000).is_err());
        assert!(start.elapsed() < TIMEOUT + Duration::from_secs(1));
    }
}
