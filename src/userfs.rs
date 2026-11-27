use std::any::Any;
use std::path::{Path, PathBuf};

use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsFuture, FsStream, OpenOptions, ReadDirMeta,
};
use dav_server::localfs::LocalFs;

use crate::suid::UgidSwitch;

#[derive(Clone)]
pub struct UserFs {
    pub fs:  LocalFs,
    // basedir and uid are only used for quota lookups.
    #[cfg_attr(not(feature = "quota"), allow(dead_code))]
    basedir: PathBuf,
    /// Target user, `None` when the server does not switch uid.
    #[cfg_attr(not(feature = "quota"), allow(dead_code))]
    uid:     Option<u32>,
}

impl UserFs {
    pub fn new(
        dir: impl AsRef<Path>,
        target_creds: Option<(u32, u32, &[u32])>,
        public: bool,
        case_insensitive: bool,
        macos: bool,
    ) -> Box<UserFs>
    {
        // uid is used for quota() calls.
        let uid = target_creds.as_ref().map(|ugid| ugid.0);

        // set up the LocalFs hooks for uid switching.
        let switch = UgidSwitch::new(target_creds);
        let blocking_guard: Box<dyn Fn() -> Box<dyn Any> + Send + Sync> =
            Box::new(move || Box::new(switch.guard()) as Box<dyn Any>);

        Box::new(UserFs {
            basedir: dir.as_ref().to_path_buf(),
            fs:      *LocalFs::new_with_fs_access_guard(
                dir,
                public,
                case_insensitive,
                macos,
                Some(blocking_guard),
            ),
            uid,
        })
    }

    /// Get `(bytes used, bytes limit)` that applies to `path` for the user of this filesystem.
    #[cfg(feature = "quota")]
    pub fn get_quota_for_path(&self, path: &Path) -> FsFuture<'_, (u64, Option<u64>)> {
        use std::os::unix::fs::MetadataExt;
        use std::sync::LazyLock;
        use std::time::Duration;

        use dav_server::fs::FsError;
        use futures::future::FutureExt;
        use moka::sync::Cache;

        use crate::cache::new_cache;
        use crate::quota::{self, QuotaInfo};

        // Keyed by (st_dev, uid): all paths on one filesystem share one entry.
        static QCACHE: LazyLock<Cache<(u64, Option<u32>), QuotaInfo>> =
            LazyLock::new(|| new_cache(Duration::from_secs(30)));

        let path = path.to_path_buf();
        let uid = self.uid;
        async move {
            // Runs with the credentials of the user, like all other filesystem access.
            let info = self
                .fs
                .blocking(move || -> Result<QuotaInfo, FsError> {
                    let key = std::fs::metadata(&path).ok().map(|meta| (meta.dev(), uid));
                    if let Some(info) = key.and_then(|key| QCACHE.get(&key)) {
                        debug!("get_quota for {:?}: from cache", path);
                        return Ok(info);
                    }
                    let info = quota::check_path(&path, uid).map_err(|err| {
                        error!("get_quota for {:?}: {}", path, err);
                        FsError::GeneralFailure
                    })?;
                    if let Some(key) = key {
                        QCACHE.insert(key, info);
                    }
                    Ok(info)
                })
                .await?;
            Ok((info.bytes_used, info.bytes_limit))
        }
        .boxed()
    }
}

impl DavFileSystem for UserFs {
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.fs.metadata(path)
    }

    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.fs.symlink_metadata(path)
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>>
    {
        self.fs.read_dir(path, meta)
    }

    fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions) -> FsFuture<'a, Box<dyn DavFile>> {
        self.fs.open(path, options)
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.fs.create_dir(path)
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.fs.remove_dir(path)
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        self.fs.remove_file(path)
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        self.fs.rename(from, to)
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        self.fs.copy(from, to)
    }

    #[cfg(feature = "quota")]
    fn get_quota(&self) -> FsFuture<'_, (u64, Option<u64>)> {
        // TODO: `DavFileSystem::get_quota` in dav-server 0.12 has no path parameter, so
        // query `self.basedir`. Pass the target path to `get_quota_for_path` once
        // upstream supports path-level quota.
        self.get_quota_for_path(&self.basedir)
    }
}
