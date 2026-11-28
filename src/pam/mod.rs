//! PAM authentication in separate processes.
//!
//! The process tree is:
//!
//! ```text
//! webdavd ──> webdavd pam-broker ──> N × webdavd pam-worker
//! ```
//!
//! - The server starts the broker once, before it drops its privileges. Thus
//!   the broker keeps the initial privileges of the server (for example root)
//!   for its full lifetime, also if the server later drops all privileges.
//! - The broker ([`broker`]) is single-threaded. It owns the workers: it starts
//!   them, sends requests to them, and replaces a worker that fails. It has
//!   the same uid as the workers, so it can always kill them.
//! - A worker ([`worker`]) runs PAM for one request at a time.
//! - The server ([`client`]) sends requests to the broker. If the broker
//!   exits, the server exits too, because it cannot start a privileged broker
//!   again.

mod broker;
mod client;
mod protocol;
#[cfg(test)]
mod tests;
mod worker;

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::process::Stdio;

use clap::builder::NonEmptyStringValueParser;
use clap::{Arg, ArgAction, ArgMatches, Command};

pub use client::{BrokerOptions, PamAuth, PamError};

/// Hidden subcommand that runs the broker.
const BROKER_SUBCOMMAND: &str = "pam-broker";
/// Hidden subcommand that runs a worker.
const WORKER_SUBCOMMAND: &str = "pam-worker";
/// Environment variable with the pid of the broker, for its workers.
const BROKER_PID_ENV: &str = "WEBDAVD_PAM_BROKER_PID";

/// Maximum number of PAM workers.
pub const MAX_WORKERS: usize = 128;

/// Adds the hidden PAM subcommands to the command line parser.
pub fn add_subcommands(cmd: Command) -> Command {
    let workers = Arg::new("WORKERS")
        .long("workers")
        .required(true)
        .value_parser(clap::value_parser!(u32).range(1..=MAX_WORKERS as i64));
    let services = Arg::new("SERVICE")
        .long("service")
        .required(true)
        .action(ArgAction::Append)
        .value_parser(NonEmptyStringValueParser::new());
    cmd.args_conflicts_with_subcommands(true)
        .disable_help_subcommand(true)
        .subcommand(
            Command::new(BROKER_SUBCOMMAND)
                .hide(true)
                .args([workers, services]),
        )
        .subcommand(Command::new(WORKER_SUBCOMMAND).hide(true))
}

/// Runs a PAM subcommand, and exits. Returns if `matches` has no PAM
/// subcommand.
///
/// Call this before the server reads its config or starts its runtime: the
/// PAM processes are single-threaded.
pub fn run_subcommand(matches: &ArgMatches) {
    match matches.subcommand() {
        Some((BROKER_SUBCOMMAND, args)) => {
            let workers = *args.get_one::<u32>("WORKERS").expect("required") as usize;
            let allowed_services = args
                .get_many::<String>("SERVICE")
                .expect("required")
                .cloned()
                .collect::<HashSet<_>>();
            run_process(BROKER_SUBCOMMAND, || broker::main(workers, allowed_services))
        },
        Some((WORKER_SUBCOMMAND, _)) => run_process(WORKER_SUBCOMMAND, worker::main),
        _ => {},
    }
}

/// Runs the PAM process `name`, and exits: with status 0 at end of input,
/// with status 1 on a fatal error.
fn run_process(name: &str, run: impl FnOnce() -> io::Result<()>) -> ! {
    set_process_name();
    env_logger::init();
    if let Err(e) = run() {
        error!("{}: {}", name, e);
        std::process::exit(1);
    }
    std::process::exit(0)
}

/// Sets the process name that `ps -e`, `top` and `pgrep` show. After `exec`
/// of /proc/self/exe, the name is "exe".
fn set_process_name() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_NAME, c"webdavd".as_ptr());
    }
}

/// How to start a PAM process.
#[derive(Debug, Clone)]
struct ProcessCommand {
    program: PathBuf,
    args:    Vec<OsString>,
    envs:    Vec<(OsString, OsString)>,
}

impl ProcessCommand {
    /// This executable, with `args`.
    fn current_exe<I, S>(args: I) -> io::Result<ProcessCommand>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Ok(ProcessCommand {
            program: current_exe()?,
            args:    args.into_iter().map(Into::into).collect(),
            envs:    Vec::new(),
        })
    }

    /// A command with stdin and stdout as pipes, and the stderr of this
    /// process.
    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.arg0(crate::PROGNAME)
            .args(&self.args)
            .envs(self.envs.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        cmd
    }
}

fn current_exe() -> io::Result<PathBuf> {
    // On Linux, /proc/self/exe refers to the file that this process runs,
    // also after the file on disk was replaced (for example by a package
    // upgrade). Thus the PAM processes always run the same version as the
    // server.
    if cfg!(target_os = "linux") {
        Ok("/proc/self/exe".into())
    } else {
        std::env::current_exe()
    }
}

/// Moves stdin and stdout to private file descriptors for the protocol, and
/// points fd 0 and 1 to /dev/null. Thus a PAM module that reads stdin or
/// writes to stdout cannot corrupt the protocol. Stderr stays as it is.
fn take_stdio() -> io::Result<(File, File)> {
    // The copies are close-on-exec, so programs that PAM modules start
    // (for example `unix_chkpwd`) do not get them.
    let input = File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let output = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let null = File::options().read(true).write(true).open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((input, output))
}

/// Prevents core dumps and tracing by other processes of the same uid,
/// because both can read passwords from memory.
fn disable_core_dumps() -> io::Result<()> {
    set_rlimit(libc::RLIMIT_CORE, 0)?;
    #[cfg(target_os = "linux")]
    check_os(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) })?;
    #[cfg(target_os = "freebsd")]
    {
        let mut arg = libc::PROC_TRACE_CTL_DISABLE;
        check_os(unsafe { procctl_self(libc::PROC_TRACE_CTL, &mut arg) })?;
    }
    Ok(())
}

/// Calls `procctl(2)` for this process.
#[cfg(target_os = "freebsd")]
unsafe fn procctl_self(cmd: libc::c_int, arg: &mut libc::c_int) -> libc::c_int {
    let pid = libc::getpid() as libc::id_t;
    libc::procctl(
        libc::P_PID,
        pid,
        cmd,
        arg as *mut libc::c_int as *mut libc::c_void,
    )
}

/// Converts the result of a libc call that returns -1 on error.
fn check_os(ret: libc::c_int) -> io::Result<()> {
    match ret {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

/// Sets the soft and hard limit of `resource` to `limit`.
fn set_rlimit(resource: RlimitResource, limit: libc::rlim_t) -> io::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    check_os(unsafe { libc::setrlimit(resource, &rlim) })
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type RlimitResource = libc::c_int;
