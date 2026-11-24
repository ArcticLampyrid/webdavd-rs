//! Filesystem space from `statvfs(3)`, the same numbers that `df` shows.

use std::io;

/// Used and available bytes of a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FsSpace {
    pub used:  u64,
    /// Bytes available to unprivileged users.
    pub avail: u64,
}

impl FsSpace {
    /// Calculate the space from raw `statvfs` block counts.
    ///
    /// Some filesystems report `f_frsize == 0`; `f_bsize` is the unit then.
    /// `f_bavail` can be larger than `f_bfree` on some filesystems, so the
    /// result does not subtract one from the other.
    fn from_counts(frsize: u64, bsize: u64, blocks: u64, bfree: u64, bavail: u64) -> Self {
        let unit = if frsize != 0 { frsize } else { bsize.max(1) };
        FsSpace {
            used:  blocks.saturating_sub(bfree).saturating_mul(unit),
            avail: bavail.saturating_mul(unit),
        }
    }

    // The field types are different on each platform, thus `as u64` is not always a no-op.
    #[allow(clippy::unnecessary_cast)]
    fn from_raw(vfs: &libc::statvfs) -> Self {
        FsSpace::from_counts(
            vfs.f_frsize as u64,
            vfs.f_bsize as u64,
            vfs.f_blocks as u64,
            vfs.f_bfree as u64,
            vfs.f_bavail as u64,
        )
    }
}

/// `fstatvfs(3)`. The file descriptor can be an `O_PATH` descriptor.
#[cfg(target_os = "linux")]
pub(super) fn fstatvfs(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<FsSpace> {
    use std::os::fd::AsRawFd;

    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `fd` is a valid descriptor and `vfs` is a writable statvfs buffer.
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), vfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs succeeded, so it initialized `vfs`.
    Ok(FsSpace::from_raw(unsafe { &vfs.assume_init() }))
}

/// `statvfs(3)`.
#[cfg(not(target_os = "linux"))]
pub(super) fn statvfs(path: &std::path::Path) -> io::Result<FsSpace> {
    use std::os::unix::ffi::OsStrExt;

    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut vfs = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `cpath` is NUL-terminated and `vfs` is a writable statvfs buffer.
    if unsafe { libc::statvfs(cpath.as_ptr(), vfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so it initialized `vfs`.
    Ok(FsSpace::from_raw(unsafe { &vfs.assume_init() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_counts() {
        let space = FsSpace::from_counts(4096, 4096, 1000, 400, 300);
        assert_eq!(
            space,
            FsSpace {
                used:  600 * 4096,
                avail: 300 * 4096,
            }
        );
    }

    #[test]
    fn bavail_larger_than_bfree() {
        let space = FsSpace::from_counts(512, 512, 100, 10, 50);
        assert_eq!(
            space,
            FsSpace {
                used:  90 * 512,
                avail: 50 * 512,
            }
        );
    }

    #[test]
    fn zero_frsize_uses_bsize() {
        assert_eq!(FsSpace::from_counts(0, 1024, 10, 4, 4).used, 6 * 1024);
        // Both zero: count in bytes instead of returning zero.
        assert_eq!(FsSpace::from_counts(0, 0, 10, 4, 4).used, 6);
    }

    #[test]
    fn bfree_larger_than_blocks() {
        assert_eq!(FsSpace::from_counts(4096, 4096, 10, 20, 20).used, 0);
    }

    #[test]
    fn large_values_saturate() {
        let space = FsSpace::from_counts(1 << 20, 4096, u64::MAX, 0, u64::MAX);
        assert_eq!(
            space,
            FsSpace {
                used:  u64::MAX,
                avail: u64::MAX,
            }
        );
        // 2^40 blocks of 64 KiB do not fit in 32 bits, but fit in 64 bits.
        let space = FsSpace::from_counts(1 << 16, 0, 1 << 40, 0, 1 << 40);
        assert_eq!(space.used, 1 << 56);
    }
}
