//! Disk space and user quota lookups for the WebDAV quota properties (RFC 4331).
//!
//! `statvfs` is the baseline on every platform. When a uid is given, the user
//! quota of the filesystem is queried as well (Linux and FreeBSD local quota,
//! NFS `rquota` with the `quota-nfs` feature). If the user quota lookup fails
//! for any reason, the result falls back to the `statvfs` values.

mod statvfs;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(feature = "quota-nfs", any(target_os = "linux", target_os = "freebsd")))]
mod nfs;

#[cfg(target_os = "freebsd")]
use freebsd as sys;
#[cfg(target_os = "linux")]
use linux as sys;

use std::io;
use std::path::Path;

use statvfs::FsSpace;

/// Disk space that applies to a path, in the shape of the RFC 4331 properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaInfo {
    /// Number of bytes in use.
    pub bytes_used:  u64,
    /// Number of bytes in use plus the number of bytes still available.
    pub bytes_limit: Option<u64>,
}

/// User quota usage and limit, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UserQuota {
    used:  u64,
    /// `None` means that no limit applies.
    limit: Option<u64>,
}

impl UserQuota {
    /// Make a `UserQuota` from byte limits where `0` means "no limit".
    /// The soft limit has precedence over the hard limit.
    #[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
    fn new(used: u64, soft: u64, hard: u64) -> Self {
        let limit = [soft, hard].into_iter().find(|&limit| limit != 0);
        UserQuota { used, limit }
    }
}

/// Get the disk space that applies to `path` for the user `uid`.
///
/// Returns an error only if the `statvfs` lookup fails.
pub fn check_path(path: &Path, uid: Option<u32>) -> io::Result<QuotaInfo> {
    let target = sys::Target::open(path)?;
    let space = target.space()?;
    let user = uid.and_then(|uid| {
        target
            .user_quota(uid)
            .inspect_err(|err| log_fallback(path, uid, err))
            .ok()
    });
    Ok(effective_quota(space, user))
}

/// Merge the filesystem space and the user quota. The available space is the
/// smaller of the two, so that `bytes_limit - bytes_used` is what the user can
/// actually write.
fn effective_quota(space: FsSpace, user: Option<UserQuota>) -> QuotaInfo {
    match user {
        Some(UserQuota {
            used,
            limit: Some(limit),
        }) => {
            let avail = limit.saturating_sub(used).min(space.avail);
            QuotaInfo {
                bytes_used:  used,
                bytes_limit: Some(used.saturating_add(avail)),
            }
        },
        _ => {
            QuotaInfo {
                bytes_used:  space.used,
                bytes_limit: Some(space.used.saturating_add(space.avail)),
            }
        },
    }
}

fn log_fallback(path: &Path, uid: u32, err: &io::Error) {
    if is_expected_error(err) {
        debug!(
            "quota: no user quota for uid {} on {:?} ({}), use statvfs",
            uid, path, err
        );
    } else {
        warn!(
            "quota: user quota lookup for uid {} on {:?} failed: {}, use statvfs",
            uid, path, err
        );
    }
}

/// Errors that occur when quota is not available, not enabled, or not permitted.
fn is_expected_error(err: &io::Error) -> bool {
    const ERRNOS: [i32; 10] = [
        libc::ENOSYS,
        libc::EINVAL,
        libc::ENOTSUP,
        libc::EOPNOTSUPP,
        libc::EPERM,
        libc::EACCES,
        libc::ENOENT,
        libc::ESRCH,
        libc::ENOTBLK,
        libc::ENODEV,
    ];
    const KINDS: [io::ErrorKind; 5] = [
        io::ErrorKind::Unsupported,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::NotFound,
    ];
    err.raw_os_error().is_some_and(|errno| ERRNOS.contains(&errno)) || KINDS.contains(&err.kind())
}

/// Platforms without user quota support: `statvfs` only.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod sys {
    use std::io;
    use std::path::Path;

    use super::statvfs::{self, FsSpace};
    use super::UserQuota;

    pub(super) struct Target<'a>(&'a Path);

    impl<'a> Target<'a> {
        pub(super) fn open(path: &'a Path) -> io::Result<Self> {
            Ok(Target(path))
        }

        pub(super) fn space(&self) -> io::Result<FsSpace> {
            statvfs::statvfs(self.0)
        }

        pub(super) fn user_quota(&self, _uid: u32) -> io::Result<UserQuota> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: FsSpace = FsSpace {
        used:  1000,
        avail: 500,
    };

    #[test]
    fn user_quota_normalizes_zero_limits() {
        assert_eq!(UserQuota::new(10, 0, 0).limit, None);
        assert_eq!(UserQuota::new(10, 100, 200).limit, Some(100));
        assert_eq!(UserQuota::new(10, 0, 200).limit, Some(200));
    }

    #[test]
    fn statvfs_only_without_user_quota() {
        let expected = QuotaInfo {
            bytes_used:  1000,
            bytes_limit: Some(1500),
        };
        assert_eq!(effective_quota(SPACE, None), expected);
        // An unlimited user quota is the same as no user quota.
        assert_eq!(effective_quota(SPACE, Some(UserQuota::new(42, 0, 0))), expected);
    }

    #[test]
    fn user_limit_below_free_space() {
        let info = effective_quota(SPACE, Some(UserQuota::new(100, 300, 0)));
        assert_eq!(
            info,
            QuotaInfo {
                bytes_used:  100,
                bytes_limit: Some(300),
            }
        );
    }

    #[test]
    fn free_space_below_user_limit() {
        let info = effective_quota(SPACE, Some(UserQuota::new(100, 10_000, 0)));
        assert_eq!(
            info,
            QuotaInfo {
                bytes_used:  100,
                bytes_limit: Some(600),
            }
        );
    }

    #[test]
    fn user_over_quota_has_no_space_left() {
        let info = effective_quota(SPACE, Some(UserQuota::new(400, 300, 0)));
        assert_eq!(
            info,
            QuotaInfo {
                bytes_used:  400,
                bytes_limit: Some(400),
            }
        );
    }

    #[test]
    fn merge_saturates() {
        let space = FsSpace {
            used:  u64::MAX,
            avail: u64::MAX,
        };
        assert_eq!(effective_quota(space, None).bytes_limit, Some(u64::MAX));
        let user = UserQuota::new(u64::MAX - 1, u64::MAX, 0);
        assert_eq!(effective_quota(space, Some(user)).bytes_limit, Some(u64::MAX));
    }

    #[test]
    fn error_classification() {
        assert!(is_expected_error(&io::Error::from_raw_os_error(libc::ENOSYS)));
        assert!(is_expected_error(&io::Error::from_raw_os_error(libc::ESRCH)));
        assert!(is_expected_error(&io::ErrorKind::TimedOut.into()));
        assert!(!is_expected_error(&io::Error::from_raw_os_error(libc::EIO)));
        assert!(!is_expected_error(&io::ErrorKind::InvalidData.into()));
    }

    #[test]
    fn check_path_fails_on_missing_path() {
        assert!(check_path(Path::new("/nonexistent/webdavd-quota-test"), None).is_err());
    }

    #[test]
    fn check_path_smoke() {
        let uid = unsafe { libc::getuid() };
        let system = check_path(Path::new("."), None).expect("statvfs on current dir");
        assert!(system.bytes_limit.is_some_and(|limit| limit >= system.bytes_used));
        let user = check_path(Path::new("."), Some(uid)).expect("quota on current dir");
        assert!(user.bytes_limit.is_some_and(|limit| limit >= user.bytes_used));
    }

    /// procfs has no quota support and no disk space: the user quota lookup
    /// fails and the result is the plain `statvfs` result.
    #[cfg(target_os = "linux")]
    #[test]
    fn check_path_falls_back_to_statvfs() {
        let expected = QuotaInfo {
            bytes_used:  0,
            bytes_limit: Some(0),
        };
        let uid = unsafe { libc::getuid() };
        assert_eq!(check_path(Path::new("/proc"), Some(uid)).unwrap(), expected);
    }
}
