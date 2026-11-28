//! The PAM broker process (`webdavd pam-broker`).
//!
//! The broker reads requests from the server on stdin, sends them to its
//! workers, and writes the responses to stdout. It is single-threaded: there
//! are no other threads when it starts a worker, and it has its own file
//! descriptor table, so clients of the server cannot use up the file
//! descriptors that it needs. Because it is single-threaded, the parent-death
//! signal of a worker is sent only when the broker process exits.
//!
//! Each worker has a supervisor task. The supervisors take requests from a
//! shared queue, and replace a worker that exits, fails, or hangs. A request
//! that the server cancels before a supervisor takes it does not go to a
//! worker. A request that already runs is not interrupted.
//!
//! A new worker must answer a `Ping` before it gets requests. If it does not,
//! the broker kills all workers and exits, instead of trying again: a worker
//! that cannot start once will most likely never start.

use std::collections::HashSet;
use std::convert::Infallible;
use std::fs::File;
use std::io;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use tokio::io::AsyncWriteExt;
use tokio::net::unix::pipe;
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::protocol::{self, AuthRequest, Method, Notification, RpcMessage, RpcResult};
use super::{disable_core_dumps, take_stdio, ProcessCommand, BROKER_PID_ENV, WORKER_SUBCOMMAND};

const PING_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a worker may take to exit after end of input.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// How to start the workers, and how many.
#[derive(Debug, Clone)]
pub(super) struct Options {
    pub worker:           ProcessCommand,
    pub workers:          usize,
    pub allowed_services: HashSet<String>,
    pub ping_timeout:     Duration,
    pub auth_timeout:     Duration,
}

impl Options {
    /// Workers that run this executable as `webdavd pam-worker`.
    fn new(workers: usize, allowed_services: HashSet<String>) -> io::Result<Options> {
        Ok(Options {
            worker: ProcessCommand::current_exe([WORKER_SUBCOMMAND])?,
            workers,
            allowed_services,
            ping_timeout: PING_TIMEOUT,
            auth_timeout: AUTH_TIMEOUT,
        })
    }
}

/// Entry point of `webdavd pam-broker`.
pub fn main(workers: usize, allowed_services: HashSet<String>) -> io::Result<()> {
    run(Options::new(workers, allowed_services)?)
}

/// Sets up the process, then serves requests until end of input.
pub(super) fn run(opts: Options) -> io::Result<()> {
    let (input, output) = take_stdio()?;
    disable_core_dumps()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(broker(opts, input, output))
}

/// An authentication request from the server, for a worker.
struct Job {
    id:  u64,
    req: AuthRequest,
}

/// Unbounded: a request waits only until the deadline of the server, which
/// then cancels it.
type JobQueue = Arc<Mutex<mpsc::UnboundedReceiver<Job>>>;

/// What the supervisors share.
#[derive(Clone)]
struct Context {
    opts:    Arc<Options>,
    queue:   JobQueue,
    replies: mpsc::UnboundedSender<(u64, RpcResult)>,
    /// Ids of the jobs that wait or run, and that the server did not cancel.
    /// A cancel removes the id; so does the response.
    live:    Arc<std::sync::Mutex<HashSet<u64>>>,
}

impl Context {
    /// Sends the response to request `id`. The job is then no longer live.
    fn reply(&self, id: u64, result: RpcResult) {
        self.live.lock().unwrap().remove(&id);
        // Fails only when the broker stops.
        let _ = self.replies.send((id, result));
    }

    fn is_live(&self, id: u64) -> bool {
        self.live.lock().unwrap().contains(&id)
    }
}

async fn broker(opts: Options, input: File, output: File) -> io::Result<()> {
    let input = pipe::Receiver::from_file(input)?;
    let output = pipe::Sender::from_file(output)?;
    let opts = Arc::new(opts);
    let workers = start_workers(&opts).await?;

    let (jobs, queue) = mpsc::unbounded_channel();
    let (replies, replies_rx) = mpsc::unbounded_channel();
    let ctx = Context {
        opts,
        queue: Arc::new(Mutex::new(queue)),
        replies,
        live: Default::default(),
    };
    let (stop, stopped) = watch::channel(false);
    let mut supervisors = JoinSet::new();
    for worker in workers {
        supervisors.spawn(supervise(worker, ctx.clone(), stopped.clone()));
    }

    // A supervisor only returns early if it cannot replace its worker.
    let outcome = tokio::select! {
        res = serve_server(input, output, jobs, &ctx, replies_rx) => res,
        Some(res) = supervisors.join_next() => Err(match res {
            Ok(Err(e)) => e,
            Ok(Ok(_)) => io::Error::other("PAM supervisor stopped"),
            Err(e) => io::Error::other(e),
        }),
    };

    // Each supervisor returns its current worker, also one that is still
    // starting, so that no worker is left behind.
    stop.send_replace(true);
    let workers = supervisors
        .join_all()
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    match outcome {
        Ok(()) => {
            debug!("pam-broker: end of input, stopping {} workers", workers.len());
            join_all(workers.into_iter().map(|worker| worker.stop(SHUTDOWN_GRACE))).await;
            Ok(())
        },
        Err(e) => {
            kill_all(workers).await;
            Err(e)
        },
    }
}

/// Starts all workers. If one does not start, kills the others.
async fn start_workers(opts: &Options) -> io::Result<Vec<Worker>> {
    let mut workers = Vec::with_capacity(opts.workers);
    let mut error = None;
    for result in join_all((0..opts.workers).map(|_| Worker::start(opts))).await {
        match result {
            Ok(worker) => workers.push(worker),
            Err(e) => {
                error.get_or_insert(e);
            },
        }
    }
    match error {
        None => Ok(workers),
        Some(e) => {
            kill_all(workers).await;
            Err(e)
        },
    }
}

async fn kill_all(workers: Vec<Worker>) {
    join_all(
        workers
            .into_iter()
            .map(|mut worker| async move { kill(&mut worker.child).await }),
    )
    .await;
}

/// Reads messages from the server and writes the responses, until end of
/// input.
async fn serve_server(
    mut input: pipe::Receiver,
    mut output: pipe::Sender,
    jobs: mpsc::UnboundedSender<Job>,
    ctx: &Context,
    mut replies: mpsc::UnboundedReceiver<(u64, RpcResult)>,
) -> io::Result<()> {
    let reading = async {
        while let Some(msg) = protocol::read_async(&mut input).await? {
            match msg {
                RpcMessage::Request {
                    id,
                    method: Method::Ping,
                } => ctx.reply(id, RpcResult::Pong),
                RpcMessage::Request {
                    id,
                    method: Method::Auth(req),
                } => {
                    if !ctx.opts.allowed_services.contains(&req.service) {
                        let error = format!("PAM service {:?} is not allowed", req.service);
                        warn!("pam-broker: {}", error);
                        ctx.reply(id, RpcResult::Unavailable(error));
                        continue;
                    }
                    ctx.live.lock().unwrap().insert(id);
                    jobs.send(Job { id, req })
                        .map_err(|_| io::Error::other("PAM broker queue closed"))?;
                },
                RpcMessage::Notification(Notification::Cancel { id }) => {
                    ctx.live.lock().unwrap().remove(&id);
                },
                RpcMessage::Response { id, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected response {} from server", id),
                    ));
                },
            }
        }
        Ok(())
    };
    let writing = async {
        while let Some((id, result)) = replies.recv().await {
            output.write_all(&RpcMessage::response_frame(id, result)).await?;
        }
        Ok(())
    };
    tokio::select! {
        res = reading => res,
        res = writing => res,
    }
}

/// Serves jobs with `worker` until `stop`. Returns the current worker, or
/// an error if a replacement worker did not start.
async fn supervise(mut worker: Worker, ctx: Context, mut stop: watch::Receiver<bool>) -> io::Result<Worker> {
    let failed = tokio::select! {
        biased;
        _ = stop.wait_for(|&stop| stop) => None,
        res = serve_jobs(&mut worker, &ctx) => res.err(),
    };
    failed.map_or(Ok(worker), Err)
}

async fn serve_jobs(worker: &mut Worker, ctx: &Context) -> io::Result<Infallible> {
    loop {
        // Check the worker first, so that a job never goes to a dead worker.
        let job = tokio::select! {
            biased;
            status = worker.child.wait() => {
                warn!("pam-broker: worker exited while idle ({})", describe(status.ok()));
                worker.replace(&ctx.opts).await?;
                continue;
            },
            job = next_job(&ctx.queue) => job,
        };
        let Some(Job { id, req }) = job else {
            // The server is gone. Wait for `stop`.
            return std::future::pending().await;
        };
        if !ctx.is_live(id) {
            debug!("pam-broker: request {} cancelled before it started", id);
            ctx.reply(id, RpcResult::Cancelled);
            continue;
        }
        match worker.call(id, Method::Auth(req), ctx.opts.auth_timeout).await {
            Ok(result @ (RpcResult::AuthOk { .. } | RpcResult::Rejected(_) | RpcResult::Unavailable(_))) => {
                ctx.reply(id, result);
            },
            outcome => {
                // Do not retry: the request itself can be the cause.
                let error = describe_outcome(outcome);
                let status = kill(&mut worker.child).await;
                warn!("pam-broker: worker failed: {} ({})", error, describe(status));
                ctx.reply(id, RpcResult::Unavailable(error));
                worker.replace(&ctx.opts).await?;
            },
        }
    }
}

async fn next_job(queue: &JobQueue) -> Option<Job> {
    queue.lock().await.recv().await
}

fn describe(status: Option<ExitStatus>) -> String {
    status.map_or_else(|| "exit status unknown".into(), |status| status.to_string())
}

fn describe_outcome(outcome: io::Result<RpcResult>) -> String {
    match outcome {
        Ok(result) => format!("unexpected result {:?}", result),
        Err(e) => e.to_string(),
    }
}

/// Kills and reaps a worker and the processes in its process group (for
/// example helpers that a PAM module started). The broker and its workers
/// have the same uid, so the kill cannot fail with `EPERM`.
async fn kill(child: &mut Child) -> Option<ExitStatus> {
    // Only before the worker is reaped: after that, its process group id can
    // belong to an unrelated process.
    if let Some(pid) = child.id() {
        unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
    }
    // Fails if the process has already been reaped; wait() then returns
    // the saved status.
    let _ = child.start_kill();
    child.wait().await.ok()
}

/// A worker process.
struct Worker {
    child:  Child,
    stdin:  ChildStdin,
    stdout: ChildStdout,
}

impl Worker {
    /// Starts a worker and sends it a `Ping`. On failure, the worker is
    /// killed and reaped.
    async fn start(opts: &Options) -> io::Result<Worker> {
        let mut worker = Worker::spawn(opts)?;
        worker.handshake(opts).await?;
        Ok(worker)
    }

    /// Replaces this worker, which has been reaped, with a new one. The new
    /// worker is stored before its `Ping`, so that the caller still owns it if
    /// the broker stops during the `Ping`.
    async fn replace(&mut self, opts: &Options) -> io::Result<()> {
        *self = Worker::spawn(opts)?;
        self.handshake(opts).await
    }

    /// Starts a worker in its own process group.
    fn spawn(opts: &Options) -> io::Result<Worker> {
        let mut child = opts
            .worker
            .command()
            .process_group(0)
            .env(BROKER_PID_ENV, std::process::id().to_string())
            .kill_on_drop(true)
            .spawn()?;
        Ok(Worker {
            stdin: child.stdin.take().expect("piped stdin"),
            stdout: child.stdout.take().expect("piped stdout"),
            child,
        })
    }

    /// Sends a `Ping`. If the worker does not answer `Pong`, kills it.
    async fn handshake(&mut self, opts: &Options) -> io::Result<()> {
        let Err(error) = protocol::ping(&mut self.stdin, &mut self.stdout, opts.ping_timeout).await else {
            return Ok(());
        };
        let status = kill(&mut self.child).await;
        Err(io::Error::other(format!(
            "PAM worker {:?} did not start: {} ({})",
            opts.worker.program,
            error,
            describe(status)
        )))
    }

    /// Sends one request and reads its response.
    async fn call(&mut self, id: u64, method: Method, limit: Duration) -> io::Result<RpcResult> {
        protocol::call(&mut self.stdin, &mut self.stdout, id, method, limit).await
    }

    /// Closes stdin, so that the worker exits. Kills the worker if it does
    /// not exit within `grace`.
    async fn stop(self, grace: Duration) {
        let Worker { mut child, stdin, .. } = self;
        drop(stdin);
        if timeout(grace, child.wait()).await.is_err() {
            kill(&mut child).await;
        }
    }
}
