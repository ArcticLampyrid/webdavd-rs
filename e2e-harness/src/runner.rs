//! Run one case: boot its VM profile in a container, and wait until the guest powers off.
//!
//! The container contract is in `images/entrypoint.sh`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use testcontainers::core::logs::LogFrame;
use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::core::{Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::ImageExt;
use tokio::runtime::Runtime;

use crate::cli::Cli;
use crate::cloud_init;
use crate::config::{Case, Catalog};
use crate::image::GuestImage;
use crate::server::{self, FileServer};

/// Mount point of the socket directory of the [`FileServer`] in the container.
const CONTAINER_SOCKET_DIR: &str = "/run/e2e";
/// Time to create, start and stop the container, in addition to the guest time limit.
const CONTAINER_OVERHEAD: Duration = Duration::from_secs(120);
const EXIT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Runs cases. All cases share one HTTP file server.
pub struct Runner {
    runtime:     Runtime,
    server:      FileServer,
    /// Container image of each VM profile, by profile name.
    images:      BTreeMap<String, GuestImage>,
    args:        BTreeMap<String, String>,
    allow_tcg:   bool,
    timeout:     Option<Duration>,
    /// Print the container output and the guest console while the case runs,
    /// instead of on failure only.
    live_output: bool,
}

impl Runner {
    /// Start the HTTP file server for the cases in `suite_dir`. The container
    /// images are built later, when a case needs them.
    pub fn start(cli: &Cli, suite_dir: &Path, catalog: &Catalog) -> Result<Runner> {
        let workspace = cli
            .workspace
            .as_deref()
            .context("--workspace is necessary to run cases")?;
        let images = catalog
            .profiles
            .iter()
            .map(|(name, profile)| (name.clone(), GuestImage::new(profile)))
            .collect();
        let runtime = Runtime::new()?;
        let server = runtime.block_on(FileServer::start(workspace, &suite_dir.join("cases")))?;
        Ok(Runner {
            runtime,
            server,
            images,
            args: cli.arg_map()?,
            allow_tcg: cli.allow_tcg,
            timeout: cli.timeout.map(Duration::from_secs),
            live_output: cli.test.nocapture,
        })
    }

    /// Run `case`. Fail if a step fails, or if the guest does not finish in time.
    pub fn run(&self, case: &Case) -> Result<()> {
        self.runtime.block_on(self.run_container(case))
    }

    async fn run_container(&self, case: &Case) -> Result<()> {
        let profile = &case.profile;
        let seed = cloud_init::seed(case, &case_env(case, &self.args)?)?;
        let image = &self.images[&profile.name];
        let timeout = self.timeout.unwrap_or(Duration::from_secs(profile.timeout_secs));
        let disks = profile.disks.iter().chain(&case.disks);

        let request = image
            .ensure()
            .await?
            .with_wait_for(WaitFor::exit(
                ExitWaitStrategy::new().with_poll_interval(EXIT_POLL_INTERVAL),
            ))
            // The guest gets the network of the host through QEMU user networking.
            // Not `with_network`: it creates a network "host" if the engine does
            // not list one, and Podman does not.
            .with_host_config_modifier(|config| config.network_mode = Some("host".to_owned()))
            // For /dev/kvm.
            .with_privileged(true)
            .with_mount(Mount::bind_mount(
                self.server.socket_dir().to_string_lossy(),
                CONTAINER_SOCKET_DIR,
            ))
            .with_env_var(
                "E2E_HTTP_SOCKET",
                format!("{CONTAINER_SOCKET_DIR}/{}", server::SOCKET_NAME),
            )
            .with_env_var("E2E_HTTP_GUEST_ADDR", server::GUEST_ADDR)
            .with_env_var("E2E_TIMEOUT", timeout.as_secs().to_string())
            .with_env_var("E2E_EXTRA_DISKS", disks.cloned().collect::<Vec<_>>().join(","))
            .with_env_var("E2E_VM_MEMORY", profile.memory_mib.to_string())
            .with_env_var("E2E_VM_CPUS", profile.cpus.to_string())
            .with_env_var("E2E_ALLOW_TCG", flag(self.allow_tcg))
            .with_env_var("E2E_STREAM_CONSOLE", flag(self.live_output))
            .with_copy_to("/payload/seed/meta-data", seed.meta_data.into_bytes())
            .with_copy_to("/payload/seed/user-data", seed.user_data.into_bytes())
            .with_startup_timeout(timeout + CONTAINER_OVERHEAD);
        let request = if self.live_output {
            let prefix = format!("[{}] ", case.name);
            request.with_log_consumer(move |frame: &LogFrame| {
                String::from_utf8_lossy(frame.bytes())
                    .lines()
                    .for_each(|line| eprintln!("{prefix}{line}"));
            })
        } else {
            request
        };

        let container = request
            .start()
            .await
            .with_context(|| format!("run container image {}", image.reference()))?;
        let status = container.exit_code().await?;
        let passed = status == Some(0);
        // With live output, the output is already on stderr.
        let output = match passed || self.live_output {
            true => String::new(),
            false => {
                let stdout = container.stdout_to_vec().await?;
                let stderr = container.stderr_to_vec().await?;
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                )
            },
        };
        container.rm().await?;
        let status = status.map_or("unknown".to_owned(), |code| code.to_string());
        ensure!(passed, "the container failed with exit status {status}\n{output}");
        Ok(())
    }
}

/// Environment of the case steps: the base URLs, and the `--arg` values that the case declares.
fn case_env(case: &Case, args: &BTreeMap<String, String>) -> Result<Vec<(String, String)>> {
    let missing: Vec<_> = case
        .args
        .iter()
        .filter(|arg| !args.contains_key(*arg))
        .map(|arg| format!("--arg {arg}=..."))
        .collect();
    ensure!(
        missing.is_empty(),
        "case {} needs {}",
        case.name,
        missing.join(" ")
    );
    let base_urls = server::base_urls(&case.name)
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value));
    let case_args = case.args.iter().map(|arg| (arg.clone(), args[arg].clone()));
    Ok(base_urls.chain(case_args).collect())
}

/// A boolean environment variable of the container.
fn flag(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::fixtures;

    #[test]
    fn case_env_has_base_urls_and_declared_args() {
        let args = BTreeMap::from([
            ("WEBDAVD_BIN".to_owned(), "target/release/webdavd".to_owned()),
            ("OTHER".to_owned(), "not declared".to_owned()),
        ]);
        let env = case_env(&fixtures::case(), &args).unwrap();
        let expected = [
            ("WORKSPACE_BASE_URL", "http://10.0.2.100:8000/workspace"),
            ("ASSETS_BASE_URL", "http://10.0.2.100:8000/cases/demo/assets"),
            ("WEBDAVD_BIN", "target/release/webdavd"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()));
        assert_eq!(env, expected);
    }

    #[test]
    fn case_env_needs_declared_args() {
        let args = BTreeMap::from([("OTHER".to_owned(), "x".to_owned())]);
        let err = case_env(&fixtures::case(), &args).unwrap_err();
        assert_eq!(err.to_string(), "case demo needs --arg WEBDAVD_BIN=...");
    }
}
