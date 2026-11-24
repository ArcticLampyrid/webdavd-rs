//! HTTP file server for the guests, on a Unix socket.
//!
//! - `GET /workspace/<path>`: file in the workspace directory.
//! - `GET /cases/<case>/assets/<path>`: file in `cases/<case>/assets/`.
//!
//! The container gets the socket directory, and QEMU forwards [`GUEST_ADDR`]
//! in the guest to the socket. The server sends only regular files inside a
//! root, after it resolves all symbolic links. All other requests get
//! `404 Not Found`.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio_util::io::ReaderStream;

/// Address of the server in the guest network.
pub const GUEST_ADDR: &str = "10.0.2.100:8000";
/// File name of the socket in [`FileServer::socket_dir`].
pub const SOCKET_NAME: &str = "http.sock";

/// Environment variables with the base URLs for the steps of `case`.
pub fn base_urls(case: &str) -> [(&'static str, String); 2] {
    [
        ("WORKSPACE_BASE_URL", format!("http://{GUEST_ADDR}/workspace")),
        (
            "ASSETS_BASE_URL",
            format!("http://{GUEST_ADDR}/cases/{case}/assets"),
        ),
    ]
}

/// A running server. It stops when the Tokio runtime stops.
pub struct FileServer {
    socket_dir: TempDir,
}

/// Canonical root directories.
struct Roots {
    workspace: PathBuf,
    cases:     PathBuf,
}

impl FileServer {
    /// Start the server in the current Tokio runtime.
    pub async fn start(workspace: &Path, cases: &Path) -> Result<FileServer> {
        let canonical = |dir: &Path| {
            dir.canonicalize()
                .with_context(|| format!("directory {}", dir.display()))
        };
        let roots = Arc::new(Roots {
            workspace: canonical(workspace)?,
            cases:     canonical(cases)?,
        });

        // Rootless Podman and rootful Docker map container users differently:
        // let all users connect.
        let socket_dir = tempfile::Builder::new().prefix("e2e-harness-").tempdir()?;
        std::fs::set_permissions(socket_dir.path(), Permissions::from_mode(0o755))?;
        let socket = socket_dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
        std::fs::set_permissions(&socket, Permissions::from_mode(0o666))?;

        let router = Router::new()
            .route("/workspace/{*path}", get(workspace_file))
            .route("/cases/{case}/assets/{*path}", get(asset_file))
            .with_state(roots);
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, router).await {
                eprintln!("e2e-harness: HTTP server stopped: {err}");
            }
        });
        Ok(FileServer { socket_dir })
    }

    /// Directory that contains the socket [`SOCKET_NAME`].
    pub fn socket_dir(&self) -> &Path {
        self.socket_dir.path()
    }
}

async fn workspace_file(State(roots): State<Arc<Roots>>, UrlPath(path): UrlPath<String>) -> Response {
    send_file(resolve(&roots.workspace, &path)).await
}

async fn asset_file(
    State(roots): State<Arc<Roots>>,
    UrlPath((case, path)): UrlPath<(String, String)>,
) -> Response {
    let file = resolve(&roots.cases, &case)
        .and_then(|case_dir| resolve(&case_dir.join("assets"), &path))
        .filter(|file| file.starts_with(&roots.cases));
    send_file(file).await
}

/// The canonical path of `relative` in `root`, if it is a regular file or a
/// directory inside `root`. `relative` can contain only normal components:
/// no `..`, no `.`, and no root.
fn resolve(root: &Path, relative: &str) -> Option<PathBuf> {
    let relative = Path::new(relative);
    if !relative
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let path = root.join(relative).canonicalize().ok()?;
    (path != root && path.starts_with(&root)).then_some(path)
}

async fn send_file(path: Option<PathBuf>) -> Response {
    let Some(file) = path.filter(|path| path.is_file()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let opened = async {
        let file = tokio::fs::File::open(&file).await?;
        let len = file.metadata().await?.len();
        std::io::Result::Ok((file, len))
    };
    match opened.await {
        Ok((file, len)) => {
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                    (header::CONTENT_LENGTH, len.to_string()),
                ],
                Body::from_stream(ReaderStream::new(file)),
            )
                .into_response()
        },
        Err(err) => {
            eprintln!("e2e-harness: read {}: {err}", file.display());
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::*;

    /// `root/` with `a.txt`, `sub/b.txt` and links, next to `outside.txt`.
    fn tree() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(root.join("sub/b.txt"), "b").unwrap();
        fs::write(dir.path().join("outside.txt"), "secret").unwrap();
        symlink("../outside.txt", root.join("escape")).unwrap();
        symlink("sub/b.txt", root.join("inside")).unwrap();
        dir
    }

    #[test]
    fn resolve_inside_root() {
        let dir = tree();
        let root = dir.path().join("root");
        let canonical = root.canonicalize().unwrap();
        assert_eq!(resolve(&root, "a.txt"), Some(canonical.join("a.txt")));
        assert_eq!(resolve(&root, "sub/b.txt"), Some(canonical.join("sub/b.txt")));
        assert_eq!(resolve(&root, "sub//b.txt"), Some(canonical.join("sub/b.txt")));
        assert_eq!(resolve(&root, "inside"), Some(canonical.join("sub/b.txt")));
    }

    #[test]
    fn reject_paths_outside_root() {
        let dir = tree();
        let root = dir.path().join("root");
        for path in [
            "",
            ".",
            "..",
            "../outside.txt",
            "sub/../a.txt",
            "./a.txt",
            "/etc/passwd",
            "escape",
            "missing",
            "a.txt\0",
        ] {
            assert_eq!(resolve(&root, path), None, "accepted {path:?}");
        }
    }

    #[tokio::test]
    async fn serve_files_on_socket() {
        let dir = tree();
        let cases = dir.path().join("cases");
        fs::create_dir_all(cases.join("demo/assets")).unwrap();
        fs::write(cases.join("demo/assets/test.py"), "print('ok')").unwrap();
        fs::write(cases.join("demo/config.yaml"), "steps: []").unwrap();
        let server = FileServer::start(&dir.path().join("root"), &cases).await.unwrap();
        let socket = server.socket_dir().join(SOCKET_NAME);

        let mode = fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o666);
        assert_eq!(get(&socket, "/workspace/sub/b.txt").await, "200 b");
        assert_eq!(
            get(&socket, "/cases/demo/assets/test.py").await,
            "200 print('ok')"
        );
        for path in [
            "/workspace/escape",
            "/workspace/%2e%2e/outside.txt",
            "/workspace/sub",
            "/cases/demo/config.yaml",
            "/cases/demo/assets/..%2fconfig.yaml",
            "/cases/%2e%2e/assets/root/a.txt",
            "/cases/missing/assets/test.py",
            "/other",
        ] {
            assert!(get(&socket, path).await.starts_with("404 "), "served {path}");
        }
    }

    /// `GET path` over the socket with HTTP/1.0: the status code and the body.
    async fn get(socket: &Path, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        let status = &response["HTTP/1.0 ".len()..][..3];
        let body = response.split_once("\r\n\r\n").unwrap().1;
        format!("{status} {body}")
    }
}
