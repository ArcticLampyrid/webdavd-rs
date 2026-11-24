//! Configuration of the VM profiles (`vm-profiles/<name>/config.yaml`) and the
//! cases (`cases/<name>/config.yaml`).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::cli::is_env_name;
use crate::server;

/// Name of the configuration file in each profile and case directory.
const CONFIG_FILE: &str = "config.yaml";

/// A guest OS, and the steps that prepare it for all cases.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Profile {
    /// Directory name in `vm-profiles/`.
    #[serde(skip)]
    pub name:         String,
    /// Disk image in the container image of the profile (see [`crate::image`]).
    pub image:        DiskImage,
    #[serde(default = "default_memory_mib")]
    pub memory_mib:   u32,
    #[serde(default = "default_cpus")]
    pub cpus:         u32,
    /// Time limit for the guest, from boot to power-off.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Sizes of blank disks, in `qemu-img` notation (such as `128M`). They come before the disks of the case.
    #[serde(default)]
    pub disks:        Vec<String>,
    /// Files that the guest writes early in the boot, before the network starts.
    #[serde(default)]
    pub write_files:  Vec<WriteFile>,
    /// Steps that run before the steps of the case.
    #[serde(default)]
    pub steps:        Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DiskImage {
    /// URL of a qcow2 image, optionally compressed (`.xz` or `.gz`).
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WriteFile {
    /// Absolute path. The parent directory must exist in the guest.
    pub path:        String,
    pub content:     String,
    /// Octal mode, such as `"0644"`.
    pub permissions: Option<String>,
}

/// One step of a profile or a case.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Step {
    Script(ScriptStep),
}

/// A script that runs as root. A non-zero exit status stops the case.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ScriptStep {
    pub name:  Option<String>,
    /// Interpreter of `run`, found in `PATH`.
    #[serde(default = "default_shell")]
    pub shell: String,
    pub run:   String,
}

/// One test case: steps that run in a new guest of one profile.
#[derive(Debug)]
pub struct Case {
    /// Directory name in `cases/`.
    pub name:    String,
    pub profile: Arc<Profile>,
    /// Sizes of blank disks, after the disks of the profile.
    pub disks:   Vec<String>,
    /// Names of the `--arg` values that the steps get as environment variables.
    pub args:    Vec<String>,
    pub steps:   Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CaseConfig {
    vm_profile: String,
    #[serde(default)]
    disks:      Vec<String>,
    #[serde(default)]
    args:       Vec<String>,
    steps:      Vec<Step>,
}

/// All profiles and cases of a suite directory.
#[derive(Debug)]
pub struct Catalog {
    pub profiles: BTreeMap<String, Arc<Profile>>,
    /// Sorted by name.
    pub cases:    Vec<Arc<Case>>,
}

impl Catalog {
    pub fn load(suite_dir: &Path) -> Result<Catalog> {
        let profiles = load_configs::<Profile>(&suite_dir.join("vm-profiles"))?
            .into_iter()
            .map(|(name, profile)| {
                let profile = Profile { name, ..profile };
                profile.validate()?;
                Ok((profile.name.clone(), Arc::new(profile)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let cases = load_configs::<CaseConfig>(&suite_dir.join("cases"))?
            .into_iter()
            .map(|(name, config)| config.into_case(name, &profiles).map(Arc::new))
            .collect::<Result<_>>()?;
        Ok(Catalog { profiles, cases })
    }
}

impl Profile {
    fn validate(&self) -> Result<()> {
        let context = || format!("vm-profile {}", self.name);
        validate_disks(&self.disks).with_context(context)?;
        validate_steps(&self.steps).with_context(context)?;
        self.write_files
            .iter()
            .try_for_each(WriteFile::validate)
            .with_context(context)
    }
}

impl WriteFile {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.path.starts_with('/'),
            "write-files: {:?} is not an absolute path",
            self.path
        );
        if let Some(mode) = &self.permissions {
            ensure!(
                (3..=4).contains(&mode.len()) && mode.chars().all(|c| c.is_digit(8)),
                "write-files {}: permissions {mode:?} is not an octal mode",
                self.path
            );
        }
        Ok(())
    }
}

impl Step {
    pub fn script(&self) -> &ScriptStep {
        match self {
            Step::Script(script) => script,
        }
    }
}

impl CaseConfig {
    fn into_case(self, name: String, profiles: &BTreeMap<String, Arc<Profile>>) -> Result<Case> {
        let context = || format!("case {name}");
        let profile = profiles
            .get(&self.vm_profile)
            .with_context(|| format!("no vm-profile {:?}", self.vm_profile))
            .with_context(context)?;
        validate_disks(&self.disks).with_context(context)?;
        validate_steps(&self.steps).with_context(context)?;
        ensure!(!self.steps.is_empty(), "case {name}: no steps");
        // The harness sets the base URLs for each case. An arg cannot replace them.
        let reserved = server::base_urls(&name).map(|(var, _)| var);
        self.args.iter().try_for_each(|arg| {
            ensure!(
                is_env_name(arg),
                "case {name}: arg {arg:?} is not a valid environment variable name"
            );
            ensure!(
                !reserved.contains(&arg.as_str()),
                "case {name}: arg {arg} is reserved"
            );
            Ok(())
        })?;
        Ok(Case {
            name,
            profile: Arc::clone(profile),
            disks: self.disks,
            args: self.args,
            steps: self.steps,
        })
    }
}

/// `<dir>/<name>/config.yaml` for each subdirectory, sorted by name. Hidden directories are ignored.
fn load_configs<T: DeserializeOwned>(dir: &Path) -> Result<Vec<(String, T)>> {
    let mut names = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .map(|entry| {
            let name = entry?.file_name();
            name.into_string()
                .map_err(|name| anyhow::anyhow!("{}: {name:?} is not UTF-8", dir.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    names.retain(|name| !name.starts_with('.') && dir.join(name).is_dir());
    names.sort();
    names
        .into_iter()
        .map(|name| {
            ensure!(
                is_valid_name(&name),
                "{}: names can contain only a-z, 0-9, '-', '_' and '.'",
                dir.join(&name).display()
            );
            let path = dir.join(&name).join(CONFIG_FILE);
            let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let config =
                serde_saphyr::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
            Ok((name, config))
        })
        .collect()
}

/// Profile and case names go into URLs and into the guest: keep them simple.
fn is_valid_name(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

/// A size for `qemu-img create`: digits with an optional unit, such as `350M`.
fn validate_disks(disks: &[String]) -> Result<()> {
    disks.iter().try_for_each(|size| {
        let digits = size.trim_end_matches(['K', 'M', 'G', 'T']);
        ensure!(
            !digits.is_empty() &&
                size.len() - digits.len() <= 1 &&
                digits.chars().all(|c| c.is_ascii_digit()),
            "disk size {size:?}: expected digits and an optional unit K, M, G or T"
        );
        Ok(())
    })
}

fn validate_steps(steps: &[Step]) -> Result<()> {
    steps.iter().map(Step::script).try_for_each(|step| {
        ensure!(
            !step.shell.is_empty() && !step.shell.contains(char::is_whitespace),
            "step {:?}: shell {:?} is not a program name",
            step.name.as_deref().unwrap_or_default(),
            step.shell
        );
        Ok(())
    })
}

fn default_memory_mib() -> u32 {
    2048
}

fn default_cpus() -> u32 {
    2
}

fn default_timeout_secs() -> u64 {
    600
}

fn default_shell() -> String {
    "sh".to_owned()
}

/// Profiles and cases for unit tests.
#[cfg(test)]
pub mod fixtures {
    use super::*;

    pub fn script(name: Option<&str>, shell: &str, run: &str) -> Step {
        Step::Script(ScriptStep {
            name:  name.map(str::to_owned),
            shell: shell.to_owned(),
            run:   run.to_owned(),
        })
    }

    /// Profile `os-1`.
    pub fn profile() -> Profile {
        Profile {
            name:         "os-1".to_owned(),
            image:        DiskImage {
                url: "https://example.org/os.qcow2".to_owned(),
            },
            memory_mib:   default_memory_mib(),
            cpus:         default_cpus(),
            timeout_secs: default_timeout_secs(),
            disks:        vec![],
            write_files:  vec![WriteFile {
                path:        "/etc/rc.conf.d/example".to_owned(),
                content:     "example_enable=\"NO\"\n".to_owned(),
                permissions: Some("0644".to_owned()),
            }],
            steps:        vec![script(Some("prepare"), "sh", "echo prepare\n")],
        }
    }

    /// Case `demo` with the arg `WEBDAVD_BIN`, on the profile `os-1`.
    pub fn case() -> Case {
        Case {
            name:    "demo".to_owned(),
            profile: Arc::new(profile()),
            disks:   vec![],
            args:    vec!["WEBDAVD_BIN".to_owned()],
            steps:   vec![
                script(None, "bash", "echo \"$WEBDAVD_BIN\"\n"),
                script(Some("it's ok"), "sh", "exit 0\n"),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"
image:
  url: https://example.org/os.qcow2.xz
write-files:
  - path: /etc/rc.conf.d/example
    content: |
      example_enable="NO"
    permissions: "0644"
steps:
  - name: prepare
    type: script
    run: echo prepare
"#;

    const CASE: &str = r#"
vm-profile: os
disks: [128M]
args: [WEBDAVD_BIN]
steps:
  - type: script
    shell: bash
    run: |
      set -eu
      echo "$WEBDAVD_BIN"
"#;

    /// A suite directory with one profile `os` and the case `example`.
    fn suite_dir(case: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in [("vm-profiles/os", PROFILE), ("cases/example", case)] {
            fs::create_dir_all(dir.path().join(path)).unwrap();
            fs::write(dir.path().join(path).join(CONFIG_FILE), text).unwrap();
        }
        fs::create_dir(dir.path().join("cases/.hidden")).unwrap();
        dir
    }

    #[test]
    fn load_profile_and_case() {
        let dir = suite_dir(CASE);
        let catalog = Catalog::load(dir.path()).unwrap();
        let profile = &catalog.profiles["os"];
        assert_eq!(profile.name, "os");
        assert_eq!(profile.image.url, "https://example.org/os.qcow2.xz");
        assert_eq!(
            (profile.memory_mib, profile.cpus, profile.timeout_secs),
            (2048, 2, 600)
        );
        assert!(profile.disks.is_empty());
        assert_eq!(profile.write_files[0].content, "example_enable=\"NO\"\n");
        assert_eq!(profile.write_files[0].permissions.as_deref(), Some("0644"));
        assert_eq!(profile.steps[0].script().shell, "sh");

        let [case] = &catalog.cases[..] else {
            panic!("expected one case, got {:?}", catalog.cases)
        };
        assert_eq!(case.name, "example");
        assert_eq!(case.profile.name, "os");
        assert_eq!(case.disks, ["128M"]);
        assert_eq!(case.args, ["WEBDAVD_BIN"]);
        let step = case.steps[0].script();
        assert_eq!((step.name.as_deref(), step.shell.as_str()), (None, "bash"));
        assert_eq!(step.run, "set -eu\necho \"$WEBDAVD_BIN\"\n");
    }

    #[test]
    fn reject_invalid_cases() {
        let invalid = [
            CASE.replace("vm-profile: os", "vm-profile: other"),
            CASE.replace("args: [WEBDAVD_BIN]", "args: [WEBDAVD-BIN]"),
            CASE.replace("args: [WEBDAVD_BIN]", "args: [ASSETS_BASE_URL]"),
            CASE.replace("[128M]", "[128MB]"),
            CASE.replace("[128M]", "['1,2']"),
            CASE.replace("shell: bash", "shell: bash -e"),
            CASE.replace("type: script", "type: reboot"),
            CASE.replace("disks:", "disk:"),
            "vm-profile: os\nsteps: []\n".to_owned(),
        ];
        for case in invalid {
            let dir = suite_dir(&case);
            assert!(Catalog::load(dir.path()).is_err(), "accepted:\n{case}");
        }
    }

    #[test]
    fn reject_invalid_profiles() {
        let invalid = [
            PROFILE.replace("/etc/rc.conf.d/example", "etc/example"),
            PROFILE.replace("\"0644\"", "\"rw-r--r--\""),
            PROFILE.replace("image:", "disk-image:"),
            format!("{PROFILE}container-image: e2e-os:latest\n"),
        ];
        for profile in invalid {
            let dir = suite_dir(CASE);
            fs::write(dir.path().join("vm-profiles/os").join(CONFIG_FILE), &profile).unwrap();
            assert!(Catalog::load(dir.path()).is_err(), "accepted:\n{profile}");
        }
    }

    #[test]
    fn disk_sizes() {
        let sizes = |sizes: &[&str]| validate_disks(&sizes.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(sizes(&["128M", "1G", "4096"]).is_ok());
        for size in ["", "M", "12MM", "1.5G", "-1M", "1m"] {
            assert!(sizes(&[size]).is_err(), "accepted {size:?}");
        }
    }
}
