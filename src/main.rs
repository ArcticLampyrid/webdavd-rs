#![doc(html_root_url = "https://docs.rs/webdav-server/0.4.0")]
//! # `webdav-server` is a webdav server that handles user-accounts.
//!
//! This is a webdav server that allows access to a users home directory,
//! just like an ancient FTP server would (remember those?).
//!
//! This is an application. There is no API documentation here.
//! If you want to build your _own_ webdav server, use the `dav-server` crate.
//!
//! See the [GitHub repository](https://github.com/ArcticLampyrid/webdav-server-rs/)
//! for documentation on how to run the server.
//!

#[macro_use]
extern crate log;

mod auth;
mod cache;
mod config;
mod rootfs;
#[doc(hidden)]
pub mod router;
mod suid;
mod tcp_cong;
mod tls;
mod unixuser;
mod userfs;

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use clap::{Arg, ArgAction, Command};
use dav_server::{davpath::DavPath, DavConfig, DavHandler, DavMethod, DavMethodSet};
use dav_server::{fakels::FakeLs, fs::GuardedFileSystem, ls::DavLockSystem};
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use http::status::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{AcctType, Auth, CaseInsensitive, Handler, Location, OnNotfound};
use crate::rootfs::RootFs;
use crate::router::MatchedRoute;
use crate::suid::proc_switch_ugid;
use crate::tls::tls_acceptor;
use crate::userfs::UserFs;

static PROGNAME: &str = "webdav-server";

// How long a client may take to complete the TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Contains "state" and a handle to the config.
#[derive(Clone)]
struct Server {
    dh:     DavHandler,
    auth:   auth::Auth,
    config: Arc<config::Config>,
}

type HttpResult = Result<http::Response<dav_server::body::Body>, io::Error>;

// Request body. It's boxed so that we can construct an empty body
// when cloning a request (see `clone_httpreq`).
pub(crate) type ReqBody = BoxBody<Bytes, hyper::Error>;
pub(crate) type HttpRequest = http::Request<ReqBody>;

// Server implementation.
impl Server {
    // Constructor.
    pub fn new(config: Arc<config::Config>, auth: auth::Auth) -> Self {
        // mostly empty handler.
        let ls = FakeLs::new() as Box<dyn DavLockSystem>;
        let dh = DavHandler::builder().locksystem(ls).build_handler();

        Server { dh, auth, config }
    }

    // check user account.
    async fn acct<'a>(
        &'a self,
        location: &Location,
        auth_user: Option<&'a String>,
        user_param: Option<&'a str>,
    ) -> Result<Option<Arc<unixuser::User>>, StatusCode>
    {
        // Get username - if any.
        let user = match auth_user.map(|u| u.as_str()).or(user_param) {
            Some(u) => u,
            None => return Ok(None),
        };

        // If account is not set, fine.
        let acct_type = location
            .accounts
            .acct_type
            .as_ref()
            .or(self.config.accounts.acct_type.as_ref());
        match acct_type {
            Some(&AcctType::Unix) => {},
            None => return Ok(None),
        };

        // check if user exists.
        let pwd = match cache::cached::unixuser(user, self.config.unix.aux_groups).await {
            Ok(pwd) => pwd,
            Err(_) => {
                debug!("acct: unix: user {} not found", user);
                return Err(StatusCode::UNAUTHORIZED);
            },
        };

        // check minimum uid
        if let Some(min_uid) = self.config.unix.min_uid {
            if pwd.uid < min_uid {
                debug!("acct: {}: uid {} too low (<{})", pwd.name, pwd.uid, min_uid);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(Some(pwd))
    }

    // return a new response::Builder with the Server and CORS header set.
    fn response_builder(&self) -> http::response::Builder {
        let mut builder = http::Response::builder();
        self.set_headers(builder.headers_mut().unwrap());
        builder
    }

    // Set Server: webdav-server-rs header, and CORS.
    fn set_headers(&self, headers: &mut http::HeaderMap<http::header::HeaderValue>) {
        let id = self
            .config
            .server
            .identification
            .as_deref()
            .unwrap_or("webdav-server-rs");
        if !id.is_empty() {
            headers.insert("server", id.parse().unwrap());
        }
        if self.config.server.cors {
            headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
            headers.insert("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,PROPFIND".parse().unwrap());
            headers.insert("Access-Control-Allow-Headers", "DNT,Depth,Range".parse().unwrap());
        }
    }

    // handle a request.
    async fn route(&self, req: HttpRequest, remote_ip: SocketAddr) -> HttpResult {
        // Get the URI path.
        let davpath = match DavPath::from_uri(req.uri()) {
            Ok(p) => p,
            Err(_) => return self.error(StatusCode::BAD_REQUEST).await,
        };
        let path = davpath.as_bytes();

        // Get the method.
        let method = match DavMethod::try_from(req.method()) {
            Ok(m) => m,
            Err(_) => return self.error(http::StatusCode::METHOD_NOT_ALLOWED).await,
        };

        // Request is stored here.
        let mut reqdata = Some(req);
        let mut got_match = false;

        // Match routes to one or more locations.
        for route in self
            .config
            .router
            .matches(path, method, &["user", "path"])
            .drain(..)
        {
            got_match = true;

            // Take the request from the option.
            let req = reqdata.take().unwrap();

            // if we might continue, store a clone of the request for the next round.
            let location = &self.config.location[*route.data];
            if let Some(OnNotfound::Continue) = location.on_notfound {
                reqdata.get_or_insert(clone_httpreq(&req));
            }

            // handle request.
            let res = self
                .handle(req, method, path, route, location, remote_ip)
                .await?;

            // no on_notfound? then this is final.
            if reqdata.is_none() || res.status() != StatusCode::NOT_FOUND {
                return Ok(res);
            }
        }

        if !got_match {
            debug!("route: no matching route for {:?}", davpath);
        }

        self.error(StatusCode::NOT_FOUND).await
    }

    // handle a request.
    async fn handle<'a, 't: 'a, 'p: 'a>(
        &'a self,
        req: HttpRequest,
        method: DavMethod,
        path: &'a [u8],
        route: MatchedRoute<'t, 'p, usize>,
        location: &'a Location,
        remote_ip: SocketAddr,
    ) -> HttpResult
    {
        // See if we matched a :user parameter
        // If so, it must be valid UTF-8, or we return NOT_FOUND.
        let user_param = match route.params[0].as_ref() {
            Some(p) => {
                match p.as_str() {
                    Some(p) => Some(p),
                    None => {
                        debug!("handle: invalid utf-8 in :user part of path");
                        return self.error(StatusCode::NOT_FOUND).await;
                    },
                }
            },
            None => None,
        };

        // Do authentication if needed.
        let auth_hdr = req.headers().typed_get::<Authorization<Basic>>();
        let do_auth = match location.auth {
            Some(Auth::True) => true,
            Some(Auth::Write) => !DavMethodSet::WEBDAV_RO.contains(method) || auth_hdr.is_some(),
            Some(Auth::False) => false,
            Some(Auth::Opportunistic) | None => auth_hdr.is_some(),
        };
        let auth_user = if do_auth {
            let user = match self.auth.auth(&req, location, remote_ip).await {
                Ok(user) => user,
                Err(status) => return self.auth_error(status, location).await,
            };
            // if there was a :user in the route, return error if it does not match.
            if user_param.is_some_and(|u| u != user) {
                debug!("handle: auth user and :user mismatch");
                return self.auth_error(StatusCode::UNAUTHORIZED, location).await;
            }
            Some(user)
        } else {
            None
        };

        // Now see if we want to do a account lookup, for uid/gid/homedir.
        let pwd = match self.acct(location, auth_user.as_ref(), user_param).await {
            Ok(pwd) => pwd,
            Err(status) => return self.auth_error(status, location).await,
        };

        // Expand "~" in the directory.
        let dir = match expand_directory(location.directory.as_str(), pwd.as_ref()) {
            Ok(d) => d,
            Err(_) => return self.error(StatusCode::NOT_FOUND).await,
        };

        // If :path matched, we can calculate the prefix.
        // If it didn't, the entire path _is_ the prefix.
        let prefix = match route.params[1].as_ref() {
            Some(p) => {
                let mut start = p.start();
                start = start.saturating_sub(1);
                &path[..start]
            },
            None => path,
        };
        let prefix = match std::str::from_utf8(prefix) {
            Ok(p) => p.to_string(),
            Err(_) => {
                debug!("handle: prefix is non-UTF8");
                return self.error(StatusCode::NOT_FOUND).await;
            },
        };

        // Get User-Agent for user-agent specific modes.
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("");

        // Case insensitivity wanted?
        let case_insensitive = match location.case_insensitive {
            Some(CaseInsensitive::True) => true,
            Some(CaseInsensitive::Ms) => user_agent.contains("Microsoft"),
            Some(CaseInsensitive::False) | None => false,
        };

        // macOS optimizations?
        let macos = user_agent.contains("WebDAVFS/") && user_agent.contains("Darwin");

        // Get the filesystem.
        let auth_ugid = if location.setuid {
            pwd.as_ref().map(|p| (p.uid, p.gid, p.groups.as_slice()))
        } else {
            None
        };
        let fs = match location.handler {
            Handler::Virtroot => {
                let auth_user = auth_user.as_ref().map(String::to_owned);
                RootFs::new(dir, auth_user, auth_ugid) as Box<dyn GuardedFileSystem<()>>
            },
            Handler::Filesystem => {
                UserFs::new(dir, auth_ugid, true, case_insensitive, macos) as Box<dyn GuardedFileSystem<()>>
            },
        };

        // Build a handler.
        let methods = location
            .methods
            .unwrap_or_else(|| DavMethodSet::from_vec(vec!["GET", "HEAD"]).unwrap());
        let hide_symlinks = location.hide_symlinks.unwrap_or(true);

        let mut config = DavConfig::new()
            .filesystem(fs)
            .strip_prefix(prefix)
            .methods(methods)
            .hide_symlinks(hide_symlinks)
            .autoindex(location.autoindex);
        if let Some(auth_user) = auth_user {
            config = config.principal(auth_user);
        }
        if let Some(indexfile) = location.indexfile.clone() {
            config = config.indexfile(indexfile);
        }

        // All set.
        self.run_davhandler(config, req).await
    }

    async fn build_error(&self, code: StatusCode, location: Option<&Location>) -> HttpResult {
        let msg = format!(
            "<error>{} {}</error>\n",
            code.as_u16(),
            code.canonical_reason().unwrap_or("")
        );
        let mut response = self
            .response_builder()
            .status(code)
            .header("Content-Type", "text/xml");
        if code == StatusCode::UNAUTHORIZED {
            let realm = location.and_then(|location| location.accounts.realm.as_ref());
            let realm = realm.or(self.config.accounts.realm.as_ref());
            let realm = realm.map(|s| s.as_str()).unwrap_or("Webdav Server");
            response = response.header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm).as_str());
        }
        Ok(response.body(msg.into()).unwrap())
    }

    async fn auth_error(&self, code: StatusCode, location: &Location) -> HttpResult {
        self.build_error(code, Some(location)).await
    }

    async fn error(&self, code: StatusCode) -> HttpResult {
        self.build_error(code, None).await
    }

    // Call the davhandler, then add headers to the response.
    async fn run_davhandler(&self, config: DavConfig, req: HttpRequest) -> HttpResult {
        let resp = self.dh.handle_with(config, req).await;
        let (mut parts, body) = resp.into_parts();
        self.set_headers(&mut parts.headers);
        Ok(http::Response::from_parts(parts, body))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // command line option processing.
    let matches = Command::new(PROGNAME)
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::new("CFG")
                .short('c')
                .long("config")
                .value_name("CFG")
                .help("configuration file (/etc/webdav-server.toml)"),
        )
        .arg(
            Arg::new("PORT")
                .short('p')
                .long("port")
                .value_name("PORT")
                .value_parser(clap::value_parser!(u16))
                .help("listen to this port on localhost only"),
        )
        .arg(
            Arg::new("DBG")
                .short('D')
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("enable debug level logging"),
        )
        .arg(
            Arg::new("DMP")
                .short('P')
                .long("print_config")
                .action(ArgAction::SetTrue)
                .help("print configuration and exit"),
        )
        .get_matches();

    if matches.get_flag("DBG") {
        use env_logger::Env;
        let level = "webdav_server=debug,dav_server=debug";
        env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
    } else {
        env_logger::init();
    }

    let port = matches.get_one::<u16>("PORT").copied();
    let cfg = matches
        .get_one::<String>("CFG")
        .map(|s| s.as_str())
        .unwrap_or("/etc/webdav-server.toml");

    // read config.
    let mut config = match config::read(cfg) {
        Err(e) => {
            eprintln!("{}: {}: {}", PROGNAME, cfg, e);
            exit(1);
        },
        Ok(c) => c,
    };
    config::check(cfg, &config);

    if matches.get_flag("DMP") {
        println!("{:#?}", config);
        exit(0);
    }

    // build routes.
    if let Err(e) = config::build_routes(cfg, &mut config) {
        eprintln!("{}: {}: {}", PROGNAME, cfg, e);
        exit(1);
    }

    if let Some(port) = port {
        let localhosts = vec![
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([0u16; 8], port)),
        ];
        config.server.listen = config::OneOrManyAddr::Many(localhosts);
    }
    let config = Arc::new(config);

    // set cache timeouts.
    if let Some(timeout) = config.unix.cache_timeout {
        cache::cached::set_pwcache_timeout(timeout);
    }

    // resolve addresses.
    let addrs = config.server.listen.clone().to_socket_addrs().unwrap_or_else(|e| {
        eprintln!("{}: {}: [server] listen: {:?}", PROGNAME, cfg, e);
        exit(1);
    });
    let tls_addrs = config.server.tls_listen.clone().to_socket_addrs().unwrap_or_else(|e| {
        eprintln!("{}: {}: [server] listen: {:?}", PROGNAME, cfg, e);
        exit(1);
    });

    // initialize auth early.
    let auth = auth::Auth::new(config.clone())?;

    // start tokio runtime and initialize the rest from within the runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async move {
        // build servers (one for each listen address).
        let dav_server = Server::new(config.clone(), auth);
        let mut servers = Vec::new();

        // Plaintext servers.
        for sockaddr in addrs {
            let listener = match make_listener(&config.server, sockaddr) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("{}: listener on {:?}: {}", PROGNAME, sockaddr, e);
                    exit(1);
                },
            };
            println!("Listening on http://{:?}", sockaddr);
            servers.push(accept_loop(listener, dav_server.clone(), None));
        }

        // TLS servers.
        if tls_addrs.len() > 0 {
            let tls_acceptor = tls_acceptor(&config.server)?;

            for sockaddr in tls_addrs {
                let listener = make_listener(&config.server, sockaddr).unwrap_or_else(|e| {
                    eprintln!("{}: listener on {:?}: {}", PROGNAME, sockaddr, e);
                    exit(1);
                });
                println!("Listening on https://{:?}", sockaddr);
                servers.push(accept_loop(listener, dav_server.clone(), Some(tls_acceptor.clone())));
            }
        }

        // drop privs.
        if let (Some(uid), Some(gid)) = (config.server.uid, config.server.gid) {
            if !suid::have_suid_privs() {
                eprintln!(
                    "{}: insufficent priviliges to switch uid/gid (not root).",
                    PROGNAME
                );
                exit(1);
            }
            let keep_privs = config.location.iter().any(|l| l.setuid);
            proc_switch_ugid(uid, gid, keep_privs);
        }

        // spawn all servers, and wait for them to finish.
        let tasks: Vec<_> = servers.into_iter().map(tokio::spawn).collect();
        for task in tasks {
            let _ = task.await;
        }

        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

// Accept connections on a listener, and serve each one on its own task.
//
// Errors on individual connections (including failed TLS handshakes)
// only affect that connection; the accept loop keeps running.
async fn accept_loop(listener: TcpListener, dav_server: Server, tls_acceptor: Option<TlsAcceptor>) {
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                if !is_connection_error(&e) {
                    // Most likely out of filedescriptors. Back off for a bit
                    // so that we do not spin on accept().
                    error!("accept error: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            },
        };
        let dav_server = dav_server.clone();
        match tls_acceptor.clone() {
            None => {
                tokio::spawn(serve_connection(dav_server, stream, remote_addr));
            },
            Some(tls_acceptor) => {
                tokio::spawn(async move {
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls_acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => serve_connection(dav_server, stream, remote_addr).await,
                        Ok(Err(e)) => debug!("{}: TLS handshake failed: {}", remote_addr, e),
                        Err(_) => debug!("{}: TLS handshake timed out", remote_addr),
                    }
                });
            },
        }
    }
}

// Errors from accept() that are about a single connection, not the listener.
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
    )
}

// Serve HTTP/1.1 and HTTP/2 on a single connection.
async fn serve_connection<S>(dav_server: Server, stream: S, remote_addr: SocketAddr)
where S: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    let service = service_fn(move |req: http::Request<Incoming>| {
        let dav_server = dav_server.clone();
        async move { dav_server.route(req.map(BodyExt::boxed), remote_addr).await }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new());
    builder.http2().timer(TokioTimer::new());
    if let Err(e) = builder.serve_connection(TokioIo::new(stream), service).await {
        debug!("{}: connection error: {}", remote_addr, e);
    }
}

// Clones a http request with an empty body.
fn clone_httpreq(req: &HttpRequest) -> HttpRequest {
    let mut builder = http::Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        .version(req.version());
    for (name, value) in req.headers().iter() {
        builder = builder.header(name, value);
    }
    let body = Empty::<Bytes>::new().map_err(|never| match never {}).boxed();
    builder.body(body).unwrap()
}

fn expand_directory(dir: &str, pwd: Option<&Arc<unixuser::User>>) -> Result<String, StatusCode> {
    // If it doesn't start with "~", skip.
    if !dir.starts_with('~') {
        return Ok(dir.to_string());
    }
    // ~whatever doesn't work.
    if dir.len() > 1 && !dir.starts_with("~/") {
        debug!("expand_directory: rejecting {}", dir);
        return Err(StatusCode::NOT_FOUND);
    }
    // must have a directory, and that dir must be UTF-8.
    let pwd = match pwd {
        Some(pwd) => pwd,
        None => {
            debug!("expand_directory: cannot expand {}: no account", dir);
            return Err(StatusCode::NOT_FOUND);
        },
    };
    let homedir = pwd.dir.to_str().ok_or(StatusCode::NOT_FOUND)?;
    Ok(format!("{}/{}", homedir, &dir[1..]))
}

// Make a new TcpListener, and if it's a V6 listener, set the
// V6_V6ONLY socket option on it.
fn make_listener(srv: &config::Server, addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, SockAddr, Socket, Type, Protocol};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if let Some(cong) = srv.congestion_control.as_ref() {
        tcp_cong::set_congestion_control(&s, cong).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("congestion control {}: {}", cong, e),
            )
        })?;
    }
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.set_tcp_nodelay(true)?;
    s.set_reuse_address(true)?;
    let addr: SockAddr = addr.into();
    s.bind(&addr)?;
    s.listen(128)?;
    let listener: std::net::TcpListener = s.into();
    TcpListener::from_std(listener)
}
