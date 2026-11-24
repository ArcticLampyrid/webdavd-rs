//! Container images that boot the guests: one for each VM profile.
//!
//! The build context is [`CONTEXT`]: all files of `images/`, embedded in the
//! binary at compile time. The harness builds the image of a profile from it,
//! with the build argument [`IMAGE_URL_ARG`] set to the `image.url` of the
//! profile. The image is `webdavd-e2e-<profile>:<signature>`. The signature is
//! a digest of all build inputs, thus a change to an input gives a new tag. The
//! harness builds an image only if no image with that tag exists, and only when
//! a case of the profile runs.

use std::sync::LazyLock;
use std::time::Instant;

use anyhow::{Context, Result};
use include_dir::{include_dir, Dir, DirEntry};
use sha2::{Digest, Sha256};
use testcontainers::core::{BuildImageOptions, CopyToContainer, CopyToContainerCollection};
use testcontainers::runners::AsyncBuilder;
use testcontainers::{BuildableImage, CopyTargetOptions, GenericImage};
use tokio::sync::OnceCell;

use crate::config::Profile;

/// Build argument with the URL of the disk image (see `images/Dockerfile`).
const IMAGE_URL_ARG: &str = "IMAGE_URL";
/// Number of hexadecimal digits of the signature in the tag.
const SIGNATURE_LEN: usize = 16;

/// The `images/` directory, embedded at compile time.
static IMAGES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/images");

/// The build context: the files of [`IMAGES`], sorted by path.
static CONTEXT: LazyLock<Vec<ContextFile>> = LazyLock::new(|| context_files(&IMAGES));

/// A file of the build context. The file mode is not included: the files in
/// the context have mode 0644.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContextFile {
    /// Path relative to `images/`, with `/` separators.
    path: &'static str,
    data: &'static [u8],
}

/// The container image of one VM profile.
#[derive(Debug)]
pub struct GuestImage {
    name:      String,
    tag:       String,
    profile:   String,
    image_url: String,
    /// Result of the first [`GuestImage::ensure`]. All cases of the profile share it.
    ready:     OnceCell<Result<GenericImage, String>>,
}

impl GuestImage {
    pub fn new(profile: &Profile) -> GuestImage {
        GuestImage {
            name:      format!("webdavd-e2e-{}", profile.name),
            tag:       signature(&profile.image.url, &CONTEXT),
            profile:   profile.name.clone(),
            image_url: profile.image.url.clone(),
            ready:     OnceCell::new(),
        }
    }

    /// `name:tag`.
    pub fn reference(&self) -> String {
        format!("{}:{}", self.name, self.tag)
    }

    /// The image, built if the container engine does not have it. Only the
    /// first call does the work. Concurrent calls wait for its result.
    pub async fn ensure(&self) -> Result<GenericImage> {
        self.ready
            .get_or_init(|| async { self.build_if_missing().await.map_err(|err| format!("{err:#}")) })
            .await
            .clone()
            .map_err(anyhow::Error::msg)
    }

    async fn build_if_missing(&self) -> Result<GenericImage> {
        let reference = self.reference();
        eprintln!(
            "e2e-harness: use image {reference} for vm-profile {}; build it if it does not exist",
            self.profile
        );
        let start = Instant::now();
        let options = BuildImageOptions::new()
            .with_skip_if_exists(true)
            .with_build_arg(IMAGE_URL_ARG, &self.image_url);
        let image = self
            .build_image_with(options)
            .await
            .with_context(|| format!("build image {reference} for vm-profile {}", self.profile))?;
        eprintln!(
            "e2e-harness: image {reference} is ready after {}s",
            start.elapsed().as_secs()
        );
        Ok(image)
    }
}

/// The build context is the exact data of the signature.
impl BuildableImage for &GuestImage {
    type Built = GenericImage;

    fn build_context(&self) -> CopyToContainerCollection {
        let files = CONTEXT
            .iter()
            .map(|file| CopyToContainer::new(file.data.to_vec(), CopyTargetOptions::new(file.path)))
            .collect();
        CopyToContainerCollection::new(files)
    }

    fn descriptor(&self) -> String {
        self.reference()
    }

    fn into_image(self) -> GenericImage {
        GenericImage::new(&self.name, &self.tag)
    }
}

/// The files of `dir` and of its subdirectories, sorted by path.
fn context_files(dir: &'static Dir<'static>) -> Vec<ContextFile> {
    fn walk(dir: &'static Dir<'static>) -> Vec<ContextFile> {
        dir.entries()
            .iter()
            .flat_map(|entry| {
                match entry {
                    DirEntry::Dir(dir) => walk(dir),
                    DirEntry::File(file) => {
                        vec![ContextFile {
                            path: file.path().to_str().expect("paths in images/ are UTF-8"),
                            data: file.contents(),
                        }]
                    },
                }
            })
            .collect()
    }
    let mut files = walk(dir);
    files.sort_by_key(|file| file.path);
    files
}

/// Truncated SHA-256 hex digest of the build inputs. Each field has a length
/// prefix, so that different inputs cannot give the same byte stream.
fn signature(image_url: &str, files: &[ContextFile]) -> String {
    let mut hasher = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(IMAGE_URL_ARG.as_bytes());
    field(image_url.as_bytes());
    for file in files {
        field(file.path.as_bytes());
        field(file.data);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()[..SIGNATURE_LEN]
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::fixtures;

    const URL: &str = "https://example.org/os.qcow2";

    fn file(path: &'static str, data: &'static str) -> ContextFile {
        ContextFile {
            path,
            data: data.as_bytes(),
        }
    }

    fn files() -> Vec<ContextFile> {
        vec![
            file("Dockerfile", "FROM debian\n"),
            file("entrypoint.sh", "#!/bin/sh\n"),
        ]
    }

    #[test]
    fn signature_is_deterministic() {
        let tag = signature(URL, &files());
        assert_eq!(tag, signature(URL, &files()));
        assert_eq!(tag.len(), SIGNATURE_LEN);
        assert!(tag
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn signature_changes_with_each_input() {
        let tag = signature(URL, &files());
        let changed = |change: fn(&mut Vec<ContextFile>)| {
            let mut files = files();
            change(&mut files);
            signature(URL, &files)
        };
        let variants = [
            signature("https://example.org/os-2.qcow2", &files()),
            changed(|files| files[0].data = b"FROM debian\n#"),
            changed(|files| files[1].data = b"#!/bin/sh\n#"),
            changed(|files| files[1].path = "start.sh"),
            changed(|files| files.push(file("extra.conf", ""))),
            changed(|files| {
                files.pop();
            }),
        ];
        for variant in variants {
            assert_ne!(variant, tag);
        }
        // The same bytes, in other fields.
        assert_ne!(
            signature(URL, &[file("ab", "c")]),
            signature(URL, &[file("a", "bc")])
        );
    }

    /// The context is sorted, has the files that the Dockerfile uses, and
    /// has the contents of `images/`.
    #[test]
    fn context_is_images_dir() {
        let images = Path::new(env!("CARGO_MANIFEST_DIR")).join("images");
        assert!(CONTEXT.is_sorted_by_key(|file| file.path));
        for path in ["Dockerfile", "entrypoint.sh"] {
            assert!(CONTEXT.iter().any(|file| file.path == path), "{path}");
        }
        for file in CONTEXT.iter() {
            assert_eq!(file.data, std::fs::read(images.join(file.path)).unwrap());
        }
    }

    #[test]
    fn image_of_profile() {
        let profile = fixtures::profile();
        let image = GuestImage::new(&profile);
        assert_eq!(image.name, "webdavd-e2e-os-1");
        assert_eq!(image.tag, signature(&profile.image.url, &CONTEXT));
        assert_eq!(image.reference(), format!("webdavd-e2e-os-1:{}", image.tag));
    }
}
