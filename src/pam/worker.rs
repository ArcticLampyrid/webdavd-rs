//! The PAM worker process (`webdavd pam-worker`).
//!
//! PAM modules are C code that can crash, hang, or leak memory, and some of
//! them are not thread-safe. Thus each worker is a separate, single-threaded
//! process that handles one request at a time: it reads requests from stdin
//! and writes responses to stdout. The broker owns the worker: when the
//! broker closes stdin, the worker exits.

use std::ffi::{CStr, CString};
use std::fmt;
use std::io::{self, Read, Write};

use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};

use super::protocol::{self, AuthRequest, Method, RpcMessage, RpcResult};
use super::{check_os, disable_core_dumps, set_rlimit, take_stdio, PamError, BROKER_PID_ENV};

/// Maximum number of open files in a worker.
const MAX_NOFILE: libc::rlim_t = 256;

/// Entry point of `webdavd pam-worker`.
pub fn main() -> io::Result<()> {
    run(pam_authenticate)
}

/// Sets up the process, then serves requests until end of input.
pub(super) fn run(authenticate: impl Fn(&AuthRequest) -> Result<String, PamError>) -> io::Result<()> {
    let (input, output) = take_stdio()?;
    exit_with_broker()?;
    disable_core_dumps()?;
    if let Err(e) = lower_nofile_limit() {
        warn!("pam-worker: cannot lower RLIMIT_NOFILE: {}", e);
    }
    serve(input, output, authenticate)
}

/// Makes the kernel stop this worker when the broker exits, also when the
/// broker is killed while this worker hangs in a PAM module.
fn exit_with_broker() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    check_os(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) })?;
    #[cfg(target_os = "freebsd")]
    {
        let mut signal = libc::SIGTERM;
        check_os(unsafe { super::procctl_self(libc::PROC_PDEATHSIG_CTL, &mut signal) })?;
    }
    // The broker can have exited before the signal was set up. Then this
    // worker has a different parent.
    let broker = std::env::var(BROKER_PID_ENV)
        .ok()
        .and_then(|pid| pid.parse::<libc::pid_t>().ok());
    match broker {
        Some(pid) if pid != unsafe { libc::getppid() } => Err(io::Error::other("PAM broker exited")),
        _ => Ok(()),
    }
}

/// Answers requests one at a time.
pub(super) fn serve(
    mut input: impl Read,
    mut output: impl Write,
    authenticate: impl Fn(&AuthRequest) -> Result<String, PamError>,
) -> io::Result<()> {
    while let Some(msg) = protocol::read(&mut input)? {
        let (id, result) = match msg {
            RpcMessage::Request {
                id,
                method: Method::Ping,
            } => (id, RpcResult::Pong),
            RpcMessage::Request {
                id,
                method: Method::Auth(req),
            } => (id, authenticate(&req).into()),
            // A worker runs one request at a time, thus nothing waits that
            // a cancel could skip.
            RpcMessage::Notification(_) => continue,
            RpcMessage::Response { id, .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected response {} from broker", id),
                ));
            },
        };
        protocol::write_frame(&mut output, &RpcMessage::response_frame(id, result))?;
    }
    Ok(())
}

/// Limits the damage of a PAM module that leaks file descriptors.
fn lower_nofile_limit() -> io::Result<()> {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    check_os(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) })?;
    set_rlimit(libc::RLIMIT_NOFILE, rlim.rlim_cur.min(MAX_NOFILE))
}

/// Authenticates the user, then checks that the account is valid (for
/// example, not expired or locked). Returns the user name after PAM
/// (`PAM_USER`), which a PAM module can change.
fn pam_authenticate(req: &AuthRequest) -> Result<String, PamError> {
    let credentials = Credentials::new(&req.user, &req.pass).map_err(PamError::Rejected)?;
    let mut context = Context::new(&req.service, Some(&req.user), credentials)
        .map_err(|e| PamError::Unavailable(format!("pam_start: {}", e)))?;
    if !req.remip.is_empty() {
        context.set_rhost(Some(&req.remip)).map_err(classify)?;
    }
    context.authenticate(Flag::NONE).map_err(classify)?;
    context.acct_mgmt(Flag::NONE).map_err(classify)?;
    if let Some(msg) = &context.conversation().error {
        return Err(PamError::Rejected(format!("PAM module error: {}", msg)));
    }
    match context.user() {
        Ok(user) if user.is_empty() => Ok(req.user.clone()),
        Ok(user) => Ok(user),
        Err(e) => Err(PamError::Unavailable(format!("PAM_USER: {}", e))),
    }
}

/// Separates rejected credentials or accounts from failures of PAM itself
/// or of its backends (for example an LDAP server that does not answer).
fn classify(e: pam_client2::Error) -> PamError {
    if is_rejection(e.code()) {
        PamError::Rejected(e.to_string())
    } else {
        PamError::Unavailable(e.to_string())
    }
}

/// Error codes that reject the credentials or the account. All other codes
/// are failures of PAM or of a backend.
fn is_rejection(code: ErrorCode) -> bool {
    use ErrorCode::*;
    matches!(
        code,
        AUTH_ERR |
            USER_UNKNOWN |
            CRED_INSUFFICIENT |
            MAXTRIES |
            ACCT_EXPIRED |
            NEW_AUTHTOK_REQD |
            PERM_DENIED |
            AUTHTOK_EXPIRED |
            CRED_EXPIRED |
            CRED_ERR |
            CONV_ERR
    )
}

/// Non-interactive PAM conversation: answers the username and password
/// prompts. Any other prompt, and any error message, fails the
/// authentication.
struct Credentials {
    user:  CString,
    pass:  CString,
    /// The first error message from a PAM module.
    error: Option<String>,
}

impl Credentials {
    fn new(user: &str, pass: &str) -> Result<Self, String> {
        let cstring = |s: &str| CString::new(s).map_err(|_| "NUL byte in credentials".to_string());
        Ok(Credentials {
            user:  cstring(user)?,
            pass:  cstring(pass)?,
            error: None,
        })
    }
}

// Never show the password, at any log level.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .field("error", &self.error)
            .finish()
    }
}

impl ConversationHandler for Credentials {
    fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        Ok(self.user.clone())
    }

    fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
        Ok(self.pass.clone())
    }

    fn text_info(&mut self, _msg: &CStr) {}

    fn error_msg(&mut self, msg: &CStr) {
        self.error
            .get_or_insert_with(|| msg.to_string_lossy().into_owned());
    }

    fn radio_prompt(&mut self, _prompt: &CStr) -> Result<bool, ErrorCode> {
        Err(ErrorCode::CONV_ERR)
    }

    fn binary_prompt(&mut self, _type: u8, _data: &[u8]) -> Result<(u8, Vec<u8>), ErrorCode> {
        Err(ErrorCode::CONV_ERR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::protocol::Notification;

    fn auth(id: u64, user: &str, pass: &str) -> RpcMessage {
        RpcMessage::Request {
            id,
            method: Method::Auth(AuthRequest {
                service: "test".into(),
                user:    user.into(),
                pass:    pass.into(),
                remip:   String::new(),
            }),
        }
    }

    #[test]
    fn serve_answers_each_request_in_order() {
        let input = [
            RpcMessage::Request {
                id:     0,
                method: Method::Ping,
            },
            auth(1, "alice", "secret"),
            RpcMessage::Notification(Notification::Cancel { id: 1 }),
            auth(2, "bob", "wrong"),
            auth(3, "carol", "down"),
        ]
        .iter()
        .flat_map(|msg| msg.to_frame().unwrap())
        .collect::<Vec<_>>();
        let mut output = Vec::new();
        let check = |req: &AuthRequest| {
            match req.pass.as_str() {
                "secret" => Ok(format!("{}-mapped", req.user)),
                "down" => Err(PamError::Unavailable("backend down".into())),
                _ => Err(PamError::Rejected("denied".into())),
            }
        };
        serve(input.as_slice(), &mut output, check).unwrap();

        let mut output = output.as_slice();
        let responses = std::iter::from_fn(|| protocol::read(&mut output).unwrap()).collect::<Vec<_>>();
        let response = |id, result| RpcMessage::Response { id, result };
        assert_eq!(
            responses,
            [
                response(0, RpcResult::Pong),
                response(
                    1,
                    RpcResult::AuthOk {
                        user: "alice-mapped".into(),
                    }
                ),
                response(2, RpcResult::Rejected("denied".into())),
                response(3, RpcResult::Unavailable("backend down".into())),
            ]
        );
    }

    #[test]
    fn serve_fails_on_response() {
        let input = RpcMessage::Response {
            id:     1,
            result: RpcResult::Pong,
        }
        .to_frame()
        .unwrap();
        let err = serve(&input[..], Vec::new(), |req: &AuthRequest| Ok(req.user.clone())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn conversation_answers_prompts() {
        let mut conv = Credentials::new("alice", "secret").unwrap();
        assert_eq!(conv.prompt_echo_on(c"login:").unwrap().as_c_str(), c"alice");
        assert_eq!(conv.prompt_echo_off(c"Password:").unwrap().as_c_str(), c"secret");
        conv.text_info(c"hello");
        assert!(conv.error.is_none());
        assert!(conv.radio_prompt(c"continue?").is_err());
        assert!(conv.binary_prompt(0, &[]).is_err());
        conv.error_msg(c"account locked");
        conv.error_msg(c"second error");
        assert_eq!(conv.error.as_deref(), Some("account locked"));
    }

    #[test]
    fn debug_redacts_password() {
        let text = format!("{:?}", Credentials::new("alice", "s3cr3t").unwrap());
        assert!(!text.contains("s3cr3t"), "password leaked: {}", text);
        assert!(text.contains("<redacted>"));
    }
}
