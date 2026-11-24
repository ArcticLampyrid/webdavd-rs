# e2e-harness

`e2e-harness` is a standalone end-to-end test harness for `webdavd`. Each test
case boots a new QEMU guest VM in a Docker or Podman container, and runs the
guest scripts of its YAML configuration.

This directory is a separate Cargo package. It is not part of the main
workspace.

## Prerequisites

- **Rust toolchain**: builds `e2e-harness` and `webdavd`.
- **Docker or Podman**: runs privileged guest containers. For rootless Podman,
  start the user socket and set `DOCKER_HOST`:
  ```sh
  systemctl --user start podman.socket
  export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
  ```
- **KVM (`/dev/kvm`)**: recommended for hardware acceleration. Without KVM,
  use `--allow-tcg` (very slow).
- **Network access**: an image build downloads the base disk image, and guests
  download packages during boot.

## Directory layout

- `e2e-harness/`: this package.
  - `src/`: the `e2e-harness` test runner.
  - `images/`: container image definition (`Dockerfile` and its files) that
    packages QEMU and a base qcow2 disk image.
- `e2e-suite/`: the test suite.
  - `vm-profiles/`: guest OS profiles (`config.yaml` with base image URL and
    setup steps).
  - `cases/`: test cases (`config.yaml` and optional `assets/`).

## VM container images

The `e2e-harness` binary contains all files of `images/`. Thus, the binary
does not need the source tree to build images, and you can run it from any
directory.

`e2e-harness` builds one container image for each VM profile. The image is
`webdavd-e2e-<profile>:<signature>`. The signature is a digest of the base
image URL and of the files of `images/` in the binary. Thus, a change to one
of these inputs gives a new image.

Before a case runs, `e2e-harness` uses the image of its profile if the
container engine has it. If not, `e2e-harness` builds the image one time, and
all cases of the profile use it. `e2e-harness` builds no image for profiles
that the selected cases do not use, and `--list` does not use the container
engine. Remove old images manually.

## Run tests

Run these commands from the repository root. `e2e-harness` finds the suite in
`e2e-suite/`.

List available cases:

```sh
cargo run --manifest-path e2e-harness/Cargo.toml -- --list
```

Run all cases. Give a workspace directory (`--workspace <DIR>`) and the binary
paths that the cases need:

```sh
cargo run --manifest-path e2e-harness/Cargo.toml -- \
  --workspace <DIR> \
  --arg LINUX_WEBDAVD_PATH=debian/webdavd \
  --arg FREEBSD_WEBDAVD_PATH=freebsd/webdavd
```

Select cases by name, or use `--skip`:

```sh
cargo run --manifest-path e2e-harness/Cargo.toml -- \
  --workspace <DIR> \
  --arg LINUX_WEBDAVD_PATH=debian/webdavd \
  linux
```

Common options:

- `--suite <DIR>`: the suite directory, with `cases/` and `vm-profiles/`
  (default: `e2e-suite`, else `.` if it has `cases/`).
- `--test-threads <N>`: maximum number of VMs that run at the same time
  (default: `2`).
- `--timeout <SECS>`: time limit for each guest VM, instead of the limit of its
  profile.
- `--allow-tcg`: use QEMU software emulation (TCG) if `/dev/kvm` is not
  available (or set `E2E_ALLOW_TCG=1`).

## Add a new case

Create `e2e-suite/cases/<case-name>/config.yaml` (case names can use `a-z`,
`0-9`, `-`, `_`, and `.`):

```yaml
vm-profile: debian-13
disks: [128M]              # optional extra blank disks (e.g. 128M, 1G)
args: [LINUX_WEBDAVD_PATH] # optional --arg names, given to steps as env vars
steps:
  - name: run check
    type: script
    run: |
      set -eux
      curl -fsS -o /usr/local/bin/webdavd "$WORKSPACE_BASE_URL/$LINUX_WEBDAVD_PATH"
      chmod 0755 /usr/local/bin/webdavd
      curl -fsS -o test.py "$ASSETS_BASE_URL/test.py"
      chmod 0755 test.py
      ./test.py
```

- Put case files and test scripts in `e2e-suite/cases/<case-name>/assets/`.
- In guest steps:
  - `$WORKSPACE_BASE_URL` serves the files of `--workspace`.
  - `$ASSETS_BASE_URL` serves the files of
    `e2e-suite/cases/<case-name>/assets/`.
  - All VM profiles install `uv` and Python 3, so test scripts can use
    `#!/usr/bin/env -S uv run --script`.
