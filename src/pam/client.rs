//! The server side: sends PAM requests to the broker.
//!
//! Requests are pipelined: each request has an `id`, and a reader task gives
//! each response to the request with the same `id`. Requests that wait for a
//! free worker queue in the broker. When a caller stops waiting (timeout or
//! drop), the client sends a `Cancel`, so that the broker skips the request
//! if it did not start yet.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use super::protocol::{self, AuthRequest, Method, Notification, RpcMessage, RpcResult};
use super::{ProcessCommand, BROKER_SUBCOMMAND};

/// How long the broker may take to start all workers.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request may take, from `auth()` until the response.
/// This includes the time in the queue of the broker.
const DEADLINE: Duration = Duration::from_secs(35);
/// How long the broker may take to exit after end of input.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How to start the broker.
#[derive(Debug, Clone)]
pub struct BrokerOptions {
    pub(super) command:         ProcessCommand,
    pub(super) startup_timeout: Duration,
    pub(super) deadline:        Duration,
}

impl BrokerOptions {
    /// A broker that runs this executable as `webdavd pam-broker`, with
    /// `workers` workers. If `log_filter` is set, the broker and its workers
    /// use it as `RUST_LOG`.
    pub fn new(
        workers: usize,
        log_filter: Option<&str>,
        allowed_services: impl IntoIterator<Item = impl Into<String>>,
    ) -> io::Result<BrokerOptions> {
        let allowed_services = allowed_services
            .into_iter()
            .map(Into::into)
            .collect::<Vec<String>>();
        if allowed_services.is_empty() || allowed_services.iter().any(String::is_empty) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PAM broker needs at least one non-empty allowed service",
            ));
        }
        let args = [BROKER_SUBCOMMAND.into(), "--workers".into(), workers.to_string()]
            .into_iter()
            .chain(
                allowed_services
                    .into_iter()
                    .flat_map(|service| ["--service".into(), service]),
            );
        let mut command = ProcessCommand::current_exe(args)?;
        command
            .envs
            .extend(log_filter.map(|filter| ("RUST_LOG".into(), filter.into())));
        Ok(BrokerOptions {
            command,
            startup_timeout: STARTUP_TIMEOUT,
            deadline: DEADLINE,
        })
    }
}

/// Why a PAM authentication did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PamError {
    /// PAM rejected the credentials or the account.
    Rejected(String),
    /// No answer from PAM: a PAM backend failed, the request was invalid or
    /// timed out, or a worker failed.
    Unavailable(String),
}

impl std::fmt::Display for PamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PamError::Rejected(msg) => write!(f, "rejected: {}", msg),
            PamError::Unavailable(msg) => write!(f, "unavailable: {}", msg),
        }
    }
}

fn unavailable<T>(msg: impl Into<String>) -> Result<T, PamError> {
    Err(PamError::Unavailable(msg.into()))
}

const BROKER_GONE: &str = "PAM broker is gone";

/// Callers that wait for a response, by request `id`.
type PendingTable = Arc<Mutex<HashMap<u64, oneshot::Sender<RpcResult>>>>;

/// Handle to the broker. When the last clone is dropped, the broker and its
/// workers stop.
#[derive(Clone)]
pub struct PamAuth {
    shared: Arc<Shared>,
}

struct Shared {
    /// Encoded messages for the broker. Unbounded, so that sending never
    /// waits; each caller sends one request and at most one `Cancel`.
    frames:   mpsc::UnboundedSender<Vec<u8>>,
    pending:  PendingTable,
    next_id:  AtomicU64,
    deadline: Duration,
}

impl PamAuth {
    /// Starts the broker, and waits until it answers a `Ping`. The broker
    /// answers after it has started all workers.
    ///
    /// The broker keeps the privileges that this process has now. Thus call
    /// this before the server drops its privileges.
    ///
    /// # Panics
    /// If the broker does not start.
    pub async fn new(opts: BrokerOptions) -> PamAuth {
        let program = &opts.command.program;
        let mut child = opts
            .command
            .command()
            .spawn()
            .unwrap_or_else(|e| panic!("PAM broker {:?} failed to start: {}", program, e));
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = child.stdout.take().expect("piped stdout");
        if let Err(e) = protocol::ping(&mut stdin, &mut stdout, opts.startup_timeout).await {
            drop(stdin);
            let status = wait_or_kill(&mut child).await;
            panic!("PAM broker {:?} failed to start: {} ({})", program, e, status);
        }

        let (frames, frames_rx) = mpsc::unbounded_channel();
        let pending = PendingTable::default();
        tokio::spawn(drive(child, stdin, stdout, frames_rx, pending.clone()));
        PamAuth {
            shared: Arc::new(Shared {
                frames,
                pending,
                // `id` 0 was the handshake.
                next_id: AtomicU64::new(1),
                deadline: opts.deadline,
            }),
        }
    }

    /// Authenticates `user` with PAM `service`. Returns the user name after
    /// PAM, which a PAM module can change.
    pub async fn auth(
        &self,
        service: &str,
        user: &str,
        pass: &str,
        remip: Option<&str>,
    ) -> Result<String, PamError> {
        let shared = &*self.shared;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let method = Method::Auth(AuthRequest {
            service: service.to_owned(),
            user:    user.to_owned(),
            pass:    pass.to_owned(),
            remip:   remip.unwrap_or_default().to_owned(),
        });
        // Encode here, so that an invalid request never reaches the broker.
        let frame = (RpcMessage::Request { id, method })
            .to_frame()
            .map_err(|e| PamError::Unavailable(e.to_string()))?;

        let (reply, response) = oneshot::channel();
        shared.pending.lock().unwrap().insert(id, reply);
        if shared.frames.send(frame).is_err() {
            shared.pending.lock().unwrap().remove(&id);
            return unavailable(BROKER_GONE);
        }
        let _cancel = CancelOnDrop { shared, id };
        match timeout(shared.deadline, response).await {
            Ok(Ok(result)) => result.into_auth(),
            Ok(Err(_)) => unavailable(BROKER_GONE),
            Err(_) => unavailable("timed out"),
        }
    }

    /// Number of callers that wait for a response.
    #[cfg(test)]
    pub(super) fn pending_requests(&self) -> usize {
        self.shared.pending.lock().unwrap().len()
    }
}

/// Cancels a request when the caller stops waiting for it: on timeout, or
/// when the `auth()` future is dropped. Does nothing after the response.
struct CancelOnDrop<'a> {
    shared: &'a Shared,
    id:     u64,
}

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        if self.shared.pending.lock().unwrap().remove(&self.id).is_none() {
            return;
        }
        let cancel = RpcMessage::Notification(Notification::Cancel { id: self.id });
        let frame = cancel.to_frame().expect("small frame");
        // Best effort: if the writer is gone, the process exits soon.
        let _ = self.shared.frames.send(frame);
    }
}

/// Sends requests to the broker and gives the responses to the callers.
///
/// When all [`PamAuth`] handles are dropped, closes the input of the broker
/// so that it stops. If the broker exits before that, exits the process.
async fn drive(
    mut child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    frames: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: PendingTable,
) {
    let outcome = tokio::select! {
        res = write_frames(stdin, frames) => res,
        Err(e) = read_responses(stdout, &pending) => Err(e),
    };
    let status = wait_or_kill(&mut child).await;
    let Err(error) = outcome else {
        debug!("PAM broker stopped ({})", status);
        return;
    };
    // This process has dropped its privileges and cannot start the
    // privileged broker again.
    let msg = format!("PAM broker exited unexpectedly ({}): {}", status, error);
    // Report once. Without a logger, use stderr. Never panic here: the
    // process must exit.
    if log_enabled!(log::Level::Error) {
        error!("{}", msg);
    } else {
        let _ = writeln!(io::stderr(), "{}: {}", crate::PROGNAME, msg);
    }
    std::process::exit(1);
}

/// Writes frames until all senders are dropped. Then closes `stdin`.
async fn write_frames(mut stdin: ChildStdin, mut frames: mpsc::UnboundedReceiver<Vec<u8>>) -> io::Result<()> {
    while let Some(frame) = frames.recv().await {
        stdin.write_all(&frame).await?;
    }
    Ok(())
}

/// Gives each response to its caller. Returns at end of output, or on an
/// invalid message.
async fn read_responses(mut stdout: ChildStdout, pending: &PendingTable) -> io::Result<Infallible> {
    while let Some(msg) = protocol::read_async(&mut stdout).await? {
        let RpcMessage::Response { id, result } = msg else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected message from broker: {:?}", msg),
            ));
        };
        let reply = pending.lock().unwrap().remove(&id);
        match reply {
            Some(reply) => {
                let _ = reply.send(result);
            },
            None => debug!("PAM response {} arrived after its caller stopped waiting", id),
        }
    }
    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end of output"))
}

/// Waits for the broker to exit, after end of its input or output. Kills it
/// if it does not exit in time. Returns its exit status as text.
async fn wait_or_kill(child: &mut Child) -> String {
    let status = match timeout(SHUTDOWN_TIMEOUT, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            // Fails with EPERM if this process has dropped its privileges.
            if let Err(e) = child.start_kill() {
                return format!("did not exit, kill: {}", e);
            }
            child.wait().await
        },
    };
    status.map_or_else(|e| e.to_string(), |status| status.to_string())
}
