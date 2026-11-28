//! Tests of the broker and the client, with fake PAM processes.
//!
//! A fake PAM process is this test executable, started with `ROLE_ENV` set.
//! It runs before `main` (see `FAKE_PROCESS_INIT`), because the test harness
//! writes to stdout. The fake processes log their events to a file, one
//! `<event> <pid>` per line.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use futures::future::join_all;

use super::broker;
use super::protocol::{self, AuthRequest, RpcMessage, RpcResult};
use super::{BrokerOptions, PamAuth, PamError, ProcessCommand};

/// `broker` or `worker`.
const ROLE_ENV: &str = "WEBDAVD_TEST_PAM_ROLE";
/// Path of the event log.
const LOG_ENV: &str = "WEBDAVD_TEST_PAM_LOG";
/// Number of workers of the fake broker.
const WORKERS_ENV: &str = "WEBDAVD_TEST_PAM_WORKERS";
/// Comma-separated PAM services that the fake broker allows.
const SERVICES_ENV: &str = "WEBDAVD_TEST_PAM_SERVICES";
/// Optional fault of the fake workers.
const FAULT_ENV: &str = "WEBDAVD_TEST_PAM_FAULT";
/// Event log of a helper test that runs in a subprocess. If it is not set,
/// the helper test does nothing.
const HELPER_LOG_ENV: &str = "WEBDAVD_TEST_PAM_HELPER_LOG";

/// How long a fake worker may take for a request.
const AUTH_TIMEOUT: Duration = Duration::from_millis(500);

#[used]
#[link_section = ".init_array"]
static FAKE_PROCESS_INIT: extern "C" fn() = fake_process_init;

extern "C" fn fake_process_init() {
    let role = std::env::var(ROLE_ENV);
    if !matches!(role.as_deref(), Ok("broker" | "worker")) {
        return;
    }
    // Runs before Rust's `lang_start`, which normally ignores SIGPIPE.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let status = match role.as_deref() {
        Ok("broker") => fake_broker(),
        Ok("worker") => fake_worker(),
        _ => unreachable!(),
    };
    std::process::exit(status);
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn fake_broker() -> i32 {
    let log = EventLog(env(LOG_ENV).into());
    log.write("broker-start");
    let services = env(SERVICES_ENV);
    let allowed_services = services.split(',').map(str::to_owned).collect();
    let opts = broker::Options {
        worker: fake_process("worker", []),
        workers: env(WORKERS_ENV).parse().unwrap(),
        allowed_services,
        ping_timeout: Duration::from_secs(5),
        auth_timeout: AUTH_TIMEOUT,
    };
    let status = if broker::run(opts).is_ok() { 0 } else { 1 };
    log.write(&format!("broker-exit-{}", status));
    status
}

fn fake_worker() -> i32 {
    let log = EventLog(env(LOG_ENV).into());
    log.write("start");
    let fault = env(FAULT_ENV);
    // "fail-after:N": the first N workers start, all others fail.
    let fail_after = fault
        .strip_prefix("fail-after:")
        .map(|n| n.parse::<usize>().unwrap());
    if fail_after.is_some_and(|n| log.count("start") > n) {
        return 1;
    }
    if fault == "bad-pong" {
        protocol::read(&mut std::io::stdin()).unwrap();
        let frame = RpcMessage::response_frame(0, RpcResult::AuthOk { user: "x".into() });
        protocol::write_frame(&mut std::io::stdout(), &frame).unwrap();
        return 0;
    }
    let authenticate = |req: &AuthRequest| {
        log.write(&format!("auth-{}", req.user));
        fake_authenticate(req)
    };
    match super::worker::run(authenticate) {
        Ok(()) => {
            log.write("exit");
            0
        },
        Err(_) => 1,
    }
}

fn fake_authenticate(req: &AuthRequest) -> Result<String, PamError> {
    match req.user.as_str() {
        "crash" => std::process::exit(3),
        "hang" => std::thread::sleep(Duration::from_secs(3600)),
        "quit" => {
            // Exit after the response is sent.
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                std::process::exit(4);
            });
        },
        user if user.starts_with("slow") => std::thread::sleep(Duration::from_millis(300)),
        _ => {},
    }
    match (req.pass.as_str(), req.user.as_str()) {
        ("secret", "alice") => Ok("alice-mapped".into()),
        ("secret", user) => Ok(user.into()),
        ("down", _) => Err(PamError::Unavailable("backend down".into())),
        _ => Err(PamError::Rejected(format!("bad password for {}", req.user))),
    }
}

/// This test executable as a fake PAM process.
fn fake_process<const N: usize>(role: &str, envs: [(&str, &str); N]) -> ProcessCommand {
    let envs = [(ROLE_ENV, role)].into_iter().chain(envs);
    ProcessCommand {
        program: super::current_exe().unwrap(),
        args:    Vec::new(),
        envs:    envs
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
    }
}

/// Event log of the fake PAM processes.
struct EventLog(PathBuf);

impl EventLog {
    fn path(&self) -> &Path {
        &self.0
    }

    /// Appends `<event> <pid>`. Does nothing if the test removed the log.
    fn write(&self, event: &str) {
        if let Ok(mut file) = OpenOptions::new().append(true).open(&self.0) {
            let _ = file.write_all(format!("{} {}\n", event, std::process::id()).as_bytes());
        }
    }

    /// Process ids that logged `event`.
    fn pids(&self, event: &str) -> Vec<libc::pid_t> {
        std::fs::read_to_string(&self.0)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(name, _)| *name == event)
            .map(|(_, pid)| pid.parse().unwrap())
            .collect()
    }

    fn count(&self, event: &str) -> usize {
        self.pids(event).len()
    }

    /// Waits until `event` has been logged `n` times.
    async fn wait_for(&self, event: &str, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.count(event) < n && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(self.count(event), n, "events {:?}", event);
    }
}

/// An empty event log file. Removes the file on drop.
struct TempLog(EventLog);

impl std::ops::Deref for TempLog {
    type Target = EventLog;

    fn deref(&self) -> &EventLog {
        &self.0
    }
}

impl TempLog {
    fn new(name: &str) -> TempLog {
        let file = format!("webdavd-pam-{}-{}.log", std::process::id(), name);
        let path = std::env::temp_dir().join(file);
        std::fs::write(&path, "").unwrap();
        TempLog(EventLog(path))
    }
}

impl Drop for TempLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path());
    }
}

/// Options for a fake broker with `workers` fake workers.
fn broker_options(log: &Path, workers: usize, fault: Option<&str>) -> BrokerOptions {
    broker_options_with_services(log, workers, fault, "test")
}

/// Options for a fake broker that allows `services`.
fn broker_options_with_services(
    log: &Path,
    workers: usize,
    fault: Option<&str>,
    services: &str,
) -> BrokerOptions {
    let workers = workers.to_string();
    let envs = [
        (LOG_ENV, log.to_str().unwrap()),
        (WORKERS_ENV, &workers),
        (SERVICES_ENV, services),
        (FAULT_ENV, fault.unwrap_or_default()),
    ];
    BrokerOptions {
        command:         fake_process("broker", envs),
        startup_timeout: Duration::from_secs(10),
        deadline:        Duration::from_secs(10),
    }
}

async fn start(log: &TempLog, workers: usize) -> PamAuth {
    let pam = PamAuth::new(broker_options(log.path(), workers, None)).await;
    assert_eq!(log.count("start"), workers);
    pam
}

async fn auth(pam: &PamAuth, user: &str, pass: &str) -> Result<String, PamError> {
    pam.auth("test", user, pass, Some("192.0.2.1")).await
}

fn is_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

#[tokio::test]
async fn concurrent_requests() {
    let log = TempLog::new("concurrent");
    let pam = start(&log, 4).await;

    let started = Instant::now();
    let requests = (0..8).map(|i| (format!("slow{}", i), ["secret", "wrong"][i % 2]));
    let requests = requests.collect::<Vec<_>>();
    let results = join_all(requests.iter().map(|(user, pass)| auth(&pam, user, pass))).await;
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "requests did not run in parallel"
    );
    // Each response goes to the request with the same id.
    for ((user, pass), result) in requests.iter().zip(results) {
        match (*pass, result) {
            ("secret", Ok(name)) => assert_eq!(&name, user),
            ("wrong", Err(PamError::Rejected(msg))) => assert_eq!(msg, format!("bad password for {}", user)),
            (_, result) => panic!("{}: unexpected {:?}", user, result),
        }
    }
    assert_eq!(log.count("start"), 4);
}

#[tokio::test]
async fn crash_during_request_replaces_worker() {
    let log = TempLog::new("crash");
    let pam = start(&log, 1).await;
    assert!(matches!(
        auth(&pam, "crash", "secret").await,
        Err(PamError::Unavailable(_))
    ));
    assert!(auth(&pam, "alice", "secret").await.is_ok());
    assert_eq!(log.count("start"), 2);
}

#[tokio::test]
async fn exit_while_idle_replaces_worker() {
    let log = TempLog::new("idle");
    let pam = start(&log, 1).await;
    assert!(auth(&pam, "quit", "secret").await.is_ok());
    log.wait_for("start", 2).await;
    assert!(auth(&pam, "alice", "secret").await.is_ok());
    assert_eq!(log.count("start"), 2);
}

#[tokio::test]
async fn timeout_kills_and_replaces_worker() {
    let log = TempLog::new("timeout");
    let pam = start(&log, 1).await;
    let started = Instant::now();
    let result = auth(&pam, "hang", "secret").await;
    assert!(matches!(result, Err(PamError::Unavailable(msg)) if msg == "timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(auth(&pam, "alice", "secret").await.is_ok());
    let pids = log.pids("start");
    assert_eq!(pids.len(), 2);
    assert!(!is_alive(pids[0]), "hung worker still runs");
}

#[tokio::test]
async fn large_request_reaches_worker() {
    let log = TempLog::new("large");
    let pam = start(&log, 1).await;
    let user = "u".repeat(1 << 20);
    let result = auth(&pam, &user, "wrong").await;
    assert_eq!(
        result,
        Err(PamError::Rejected(format!("bad password for {}", user)))
    );
    assert_eq!(auth(&pam, &user, "secret").await, Ok(user));
    assert_eq!(log.count("start"), 1);
}

#[tokio::test]
async fn service_allowlist_and_user_mapping() {
    let log = TempLog::new("services");
    let opts = broker_options_with_services(log.path(), 1, None, "test,other");
    let pam = PamAuth::new(opts).await;
    let result = pam.auth("sshd", "alice", "secret", Some("192.0.2.1")).await;
    assert!(
        matches!(&result, Err(PamError::Unavailable(msg)) if msg.contains("not allowed")),
        "{:?}",
        result
    );
    // The request never reached a worker.
    assert_eq!(log.count("auth-alice"), 0);
    // Allowed services work, and PAM_USER mapping is returned.
    assert_eq!(
        pam.auth("test", "alice", "secret", None).await,
        Ok("alice-mapped".into())
    );
    assert_eq!(pam.auth("other", "bob", "secret", None).await, Ok("bob".into()));
    assert_eq!(log.count("auth-alice"), 1);
    assert_eq!(log.count("start"), 1);
}

#[tokio::test]
async fn backend_failure_is_unavailable_and_keeps_worker() {
    let log = TempLog::new("backend");
    let pam = start(&log, 1).await;
    let result = auth(&pam, "bob", "down").await;
    assert_eq!(result, Err(PamError::Unavailable("backend down".into())));
    assert!(auth(&pam, "bob", "secret").await.is_ok());
    assert_eq!(log.count("start"), 1);
}

#[tokio::test]
async fn requests_queue_for_a_free_worker() {
    let log = TempLog::new("queue");
    let pam = start(&log, 1).await;
    // More requests than workers: they wait in the queue of the broker, and
    // all succeed.
    let started = Instant::now();
    let users = (0..4).map(|i| format!("slow{}", i)).collect::<Vec<_>>();
    let results = join_all(users.iter().map(|user| auth(&pam, user, "secret"))).await;
    for (user, result) in users.iter().zip(results) {
        assert_eq!(result.as_ref(), Ok(user));
    }
    assert!(started.elapsed() >= Duration::from_millis(4 * 300));
    assert_eq!(pam.pending_requests(), 0);
    assert_eq!(log.count("start"), 1);
}

#[tokio::test]
async fn cancelled_requests_skip_worker() {
    let log = TempLog::new("cancel");
    let pam = start(&log, 1).await;
    // Keep the only worker busy.
    let busy = tokio::spawn({
        let pam = pam.clone();
        async move { auth(&pam, "slow-busy", "secret").await }
    });
    log.wait_for("auth-slow-busy", 1).await;

    // These requests wait in the queue of the broker, and their callers stop
    // waiting.
    for i in 0..3 {
        let user = format!("slow-queued{}", i);
        let result = tokio::time::timeout(Duration::from_millis(20), auth(&pam, &user, "secret")).await;
        assert!(result.is_err(), "request {} did not wait", i);
    }
    assert_eq!(pam.pending_requests(), 1);

    assert_eq!(busy.await.unwrap(), Ok("slow-busy".into()));
    // The broker skips the cancelled requests, so this one does not wait
    // for them.
    let started = Instant::now();
    assert_eq!(auth(&pam, "bob", "secret").await, Ok("bob".into()));
    assert!(started.elapsed() < Duration::from_millis(300));
    for i in 0..3 {
        let event = format!("auth-slow-queued{}", i);
        assert_eq!(log.count(&event), 0, "{} reached a worker", event);
    }
    assert_eq!(pam.pending_requests(), 0);
    assert_eq!(log.count("start"), 1);
}

/// Starts a broker whose workers have `fault`. Returns the panic message.
async fn startup_panic(name: &str, workers: usize, fault: &str) -> (String, TempLog) {
    let log = TempLog::new(name);
    let opts = broker_options(log.path(), workers, Some(fault));
    let Err(error) = tokio::spawn(PamAuth::new(opts)).await else {
        panic!("broker started");
    };
    let panic = error.into_panic();
    let msg = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    (msg, log)
}

#[tokio::test]
async fn bad_pong_panics() {
    let (msg, log) = startup_panic("bad-pong", 1, "bad-pong").await;
    assert!(msg.contains("failed to start"), "{}", msg);
    assert_eq!(log.count("broker-exit-1"), 1);
}

#[tokio::test]
async fn startup_failure_kills_started_workers() {
    // The first two workers start, the third fails.
    let (msg, log) = startup_panic("partial-start", 3, "fail-after:2").await;
    assert!(msg.contains("failed to start"), "{}", msg);
    assert_eq!(log.count("start"), 3);
    assert_eq!(log.count("broker-exit-1"), 1);
    assert!(log.pids("start").into_iter().all(|pid| !is_alive(pid)));
}

/// Runs in a subprocess (see `restart_failure_exits_process`), because it
/// exits the process.
#[tokio::test]
#[ignore]
async fn restart_failure_helper() {
    let Ok(log) = std::env::var(HELPER_LOG_ENV) else {
        return;
    };
    let pam = PamAuth::new(broker_options(Path::new(&log), 2, Some("fail-after:2"))).await;
    assert!(auth(&pam, "crash", "secret").await.is_err());
    // Wait for the broker to exit, and then this process.
    tokio::time::sleep(Duration::from_secs(10)).await;
    panic!("process did not exit after restart failure");
}

#[test]
fn restart_failure_exits_process() {
    let log = TempLog::new("fail-restart");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "pam::tests::restart_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .env(HELPER_LOG_ENV, log.path())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr);
    assert!(
        stderr.contains("PAM broker exited unexpectedly"),
        "stderr: {}",
        stderr
    );

    // Two workers, the replacement of the crashed one, and nothing more.
    assert_eq!(log.count("start"), 3);
    assert_eq!(log.count("broker-exit-1"), 1);
    // The broker killed the healthy worker: it did not exit at end of input.
    assert_eq!(log.count("exit"), 0);
    assert!(log.pids("start").into_iter().all(|pid| !is_alive(pid)));
}

#[tokio::test]
async fn drop_stops_broker_and_workers() {
    let log = TempLog::new("drop");
    let pam = start(&log, 2).await;
    let other = pam.clone();
    assert!(auth(&pam, "alice", "secret").await.is_ok());
    drop(pam);
    assert!(auth(&other, "alice", "secret").await.is_ok());
    assert_eq!(log.count("exit"), 0);
    drop(other);
    log.wait_for("exit", 2).await;
    log.wait_for("broker-exit-0", 1).await;
    assert_eq!(log.count("start"), 2);
}
