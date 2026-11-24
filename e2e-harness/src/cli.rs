//! Command line: harness options, plus the standard test runner options of `libtest-mimic`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;

/// Number of VMs that run at the same time, if `--test-threads` is not given.
/// Each VM uses 2 GiB of memory by default.
const DEFAULT_TEST_THREADS: usize = 2;

/// Run the webdavd E2E cases of a suite, each in a new guest VM.
///
/// Each case runs in a container that boots its VM profile. The guest gets
/// the workspace and the case assets over HTTP. Standard test runner options
/// (filters, --list, --test-threads, --format, ...) select and report the
/// cases. --test-threads is 2 by default.
#[derive(Parser, Debug)]
#[command(name = "e2e-harness")]
pub struct Cli {
    /// Directory that the guest gets at $WORKSPACE_BASE_URL. Required to run cases.
    #[arg(long, value_name = "DIR")]
    pub workspace: Option<PathBuf>,

    /// Value for an argument that a case declares, given to its steps as an environment variable.
    #[arg(long = "arg", value_name = "KEY=VALUE", value_parser = parse_arg)]
    pub args: Vec<(String, String)>,

    /// Suite directory with `cases/` and `vm-profiles/` [default: `e2e-suite`, else the current directory].
    #[arg(long, value_name = "DIR")]
    pub suite: Option<PathBuf>,

    /// Use software emulation (TCG) if KVM is not available. Very slow.
    #[arg(long, env = "E2E_ALLOW_TCG")]
    pub allow_tcg: bool,

    /// Time limit for each guest VM in seconds, instead of the `timeout-secs` of its profile.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,

    #[command(flatten)]
    pub test: libtest_mimic::Arguments,
}

impl Cli {
    /// Parse the command line, and apply the default number of test threads.
    pub fn parse_with_defaults() -> Self {
        let mut cli = Cli::parse();
        cli.test.test_threads.get_or_insert(DEFAULT_TEST_THREADS);
        cli
    }

    /// The `--suite`, else `e2e-suite` or the current directory, whichever has `cases/`.
    pub fn suite_dir(&self) -> Result<PathBuf> {
        match &self.suite {
            Some(dir) => Ok(dir.clone()),
            None => {
                ["e2e-suite", "."]
                    .into_iter()
                    .map(PathBuf::from)
                    .find(|dir| dir.join("cases").is_dir())
                    .context("no cases/ in e2e-suite/ or the current directory: use --suite")
            },
        }
    }

    /// The `--arg` values by key. A key can occur only once.
    pub fn arg_map(&self) -> Result<BTreeMap<String, String>> {
        self.args
            .iter()
            .try_fold(BTreeMap::new(), |mut map, (key, value)| {
                if map.insert(key.clone(), value.clone()).is_some() {
                    bail!("--arg {key}: given more than once");
                }
                Ok(map)
            })
    }
}

/// True if `name` is a valid environment variable name for a POSIX shell.
pub fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic()) &&
        chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// `KEY=VALUE`, with an environment variable name as key.
fn parse_arg(text: &str) -> Result<(String, String)> {
    let (key, value) = text
        .split_once('=')
        .with_context(|| format!("{text:?}: expected KEY=VALUE"))?;
    ensure!(
        is_env_name(key),
        "{key:?} is not a valid environment variable name"
    );
    Ok((key.to_owned(), value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["e2e-harness"].iter().chain(args))
    }

    #[test]
    fn harness_and_runner_options() {
        let cli = parse(&[
            "--workspace",
            "/src",
            "--suite",
            "/suite",
            "--arg",
            "WEBDAVD_LINUX_BIN=target/release/webdavd",
            "--arg",
            "EMPTY=",
            "--timeout",
            "900",
            "--test-threads",
            "4",
            "--format",
            "terse",
            "--skip",
            "freebsd",
            "linux",
        ])
        .unwrap();
        assert_eq!(cli.workspace, Some(PathBuf::from("/src")));
        assert_eq!(cli.suite_dir().unwrap(), PathBuf::from("/suite"));
        assert_eq!(
            cli.arg_map().unwrap()["WEBDAVD_LINUX_BIN"],
            "target/release/webdavd"
        );
        assert_eq!(cli.arg_map().unwrap()["EMPTY"], "");
        assert_eq!(cli.timeout, Some(900));
        assert_eq!(cli.test.test_threads, Some(4));
        assert_eq!(cli.test.skip, ["freebsd"]);
        assert_eq!(cli.test.filter.as_deref(), Some("linux"));
    }

    #[test]
    fn list_needs_no_harness_options() {
        let cli = parse(&["--list"]).unwrap();
        assert!(cli.test.list);
        assert_eq!(cli.workspace, None);
    }

    #[test]
    fn invalid_args() {
        assert!(parse(&["--arg", "NO_VALUE"]).is_err());
        assert!(parse(&["--arg", "=value"]).is_err());
        assert!(parse(&["--arg", "1ST=value"]).is_err());
        assert!(parse(&["--arg", "A-B=value"]).is_err());
        let twice = parse(&["--arg", "A=1", "--arg", "A=2"]).unwrap();
        assert!(twice.arg_map().is_err());
    }

    #[test]
    fn env_names() {
        assert!(is_env_name("WEBDAVD_BIN"));
        assert!(is_env_name("_x1"));
        assert!(!is_env_name(""));
        assert!(!is_env_name("9A"));
        assert!(!is_env_name("A B"));
    }
}
