//! VM-based end-to-end test harness for `webdavd`.
//!
//! Each case in `cases/` of the suite directory runs in a new guest of a
//! profile in `vm-profiles/`:
//!
//! - [`config`] loads the profiles and the cases.
//! - [`server`] serves the workspace and the case assets to the guests.
//! - [`cloud_init`] gives the steps to the guest as a cloud-init seed.
//! - [`image`] builds the container image of each profile, if it is missing,
//!   from the files of `images/` that the binary contains.
//! - [`runner`] boots the guest in a container, and waits for the result.
//!
//! `libtest-mimic` selects, runs and reports the cases.

mod cli;
mod cloud_init;
mod config;
mod image;
mod runner;
mod server;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use libtest_mimic::{Conclusion, Trial};

use crate::cli::Cli;
use crate::config::{Case, Catalog};
use crate::runner::Runner;

fn main() -> ExitCode {
    let cli = Cli::parse_with_defaults();
    match run(&cli) {
        Ok(conclusion) => conclusion.exit_code(),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        },
    }
}

fn run(cli: &Cli) -> Result<Conclusion> {
    let suite_dir = cli.suite_dir()?;
    let catalog = Catalog::load(&suite_dir)?;
    // --list runs no case: no server and no --workspace.
    let runner = match cli.test.list {
        true => None,
        false => Some(Arc::new(Runner::start(cli, &suite_dir, &catalog)?)),
    };
    let trials = catalog
        .cases
        .iter()
        .map(|case| trial(Arc::clone(case), runner.clone()))
        .collect();
    Ok(libtest_mimic::run(&cli.test, trials))
}

/// A test named after the case, with the profile as its kind.
fn trial(case: Arc<Case>, runner: Option<Arc<Runner>>) -> Trial {
    let kind = case.profile.name.clone();
    Trial::test(case.name.clone(), move || {
        let runner = runner.expect("cases run only without --list");
        runner.run(&case).map_err(|err| format!("{err:#}").into())
    })
    .with_kind(kind)
}
