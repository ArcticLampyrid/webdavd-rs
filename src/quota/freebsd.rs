//! FreeBSD user quota with `quotactl(2)` (UFS).

use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::statvfs::{self, FsSpace};
use super::UserQuota;

/// Unit of the block fields in `struct dqblk`.
const DEV_BSIZE: u64 = 512;

/// `struct dqblk` from `<ufs/ufs/quota.h>` (64-bit version, `Q_GETQUOTA`).
#[repr(C)]
#[derive(Default)]
struct Dqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curblocks:  u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      i64,
    dqb_itime:      i64,
}

extern "C" {
    fn quotactl(path: *const c_char, cmd: c_int, id: c_int, addr: *mut c_void) -> c_int;
}

/// `QCMD(cmd, type)` from `<ufs/ufs/quota.h>`.
const fn qcmd(cmd: c_int, kind: c_int) -> c_int {
    (cmd << 8) | (kind & 0x00ff)
}

pub(super) struct Target<'a> {
    path:  &'a Path,
    cpath: CString,
}

impl<'a> Target<'a> {
    pub(super) fn open(path: &'a Path) -> io::Result<Self> {
        let cpath = CString::new(path.as_os_str().as_bytes())?;
        Ok(Target { path, cpath })
    }

    pub(super) fn space(&self) -> io::Result<FsSpace> {
        statvfs::statvfs(self.path)
    }

    pub(super) fn user_quota(&self, uid: u32) -> io::Result<UserQuota> {
        #[cfg(feature = "quota-nfs")]
        if let Some(source) = self.nfs_source()? {
            return super::nfs::user_quota(&source, "nfs", None, uid);
        }

        let mut dq = Dqblk::default();
        let cmd = qcmd(libc::Q_GETQUOTA, libc::USRQUOTA);
        // SAFETY: `cpath` is NUL-terminated; Q_GETQUOTA writes one dqblk to `dq`.
        let rc = unsafe {
            quotactl(
                self.cpath.as_ptr(),
                cmd,
                uid as c_int,
                &mut dq as *mut Dqblk as *mut c_void,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(UserQuota::new(
            dq.dqb_curblocks.saturating_mul(DEV_BSIZE),
            dq.dqb_bsoftlimit.saturating_mul(DEV_BSIZE),
            dq.dqb_bhardlimit.saturating_mul(DEV_BSIZE),
        ))
    }

    /// The `host:/path` mount source if the path is on an NFS mount.
    #[cfg(feature = "quota-nfs")]
    fn nfs_source(&self) -> io::Result<Option<String>> {
        use std::ffi::CStr;

        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `cpath` is NUL-terminated and `fs` is a writable statfs buffer.
        if unsafe { libc::statfs(self.cpath.as_ptr(), fs.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: statfs succeeded, so it initialized `fs`.
        let fs = unsafe { fs.assume_init() };
        // SAFETY: the kernel NUL-terminates both name fields.
        let (fstype, source) = unsafe {
            (
                CStr::from_ptr(fs.f_fstypename.as_ptr()),
                CStr::from_ptr(fs.f_mntfromname.as_ptr()),
            )
        };
        Ok((fstype.to_bytes() == b"nfs").then(|| source.to_string_lossy().into_owned()))
    }
}
