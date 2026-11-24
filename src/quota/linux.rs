//! Linux user quota with `quotactl_fd(2)`, and `quotactl(2)` on the block
//! device from `/proc/self/mountinfo` as a fallback.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::statvfs::{self, FsSpace};
use super::UserQuota;

/// Unit of the `dqb_bsoftlimit` and `dqb_bhardlimit` fields (`QIF_DQBLKSIZE`).
const QIF_DQBLKSIZE: u64 = 1024;

/// An opened path. The `O_PATH` descriptor is used for both `fstatvfs` and
/// `quotactl_fd`: it needs no read permission and has no side effects on
/// special files.
pub(super) struct Target<'a> {
    path: &'a Path,
    file: File,
}

impl<'a> Target<'a> {
    pub(super) fn open(path: &'a Path) -> io::Result<Self> {
        let file = File::options().read(true).custom_flags(libc::O_PATH).open(path)?;
        Ok(Target { path, file })
    }

    pub(super) fn space(&self) -> io::Result<FsSpace> {
        statvfs::fstatvfs(self.file.as_fd())
    }

    pub(super) fn user_quota(&self, uid: u32) -> io::Result<UserQuota> {
        match quotactl_fd(self.file.as_fd(), uid) {
            // Kernel < 5.14, or a filesystem without quotactl support (such as NFS).
            Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => self.mount_user_quota(uid),
            result => result,
        }
    }

    /// Find the mount of this path, then query its block device or NFS server.
    fn mount_user_quota(&self, uid: u32) -> io::Result<UserQuota> {
        let dev = self.file.metadata()?.dev();
        let path = std::fs::canonicalize(self.path)?;
        let mounts = read_mounts()?;
        let mount = find_mount(&mounts, dev, &path).ok_or(io::ErrorKind::NotFound)?;

        #[cfg(feature = "quota-nfs")]
        if mount.is_nfs() {
            return super::nfs::user_quota(&mount.source, &mount.fstype, mount.option("addr"), uid);
        }

        let device = mount
            .device_candidates()
            .into_iter()
            .find(|device| device.exists())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTBLK))?;
        quotactl_device(&device, uid)
    }
}

fn quota_from_dqblk(dq: &libc::dqblk) -> UserQuota {
    UserQuota::new(
        dq.dqb_curspace,
        dq.dqb_bsoftlimit.saturating_mul(QIF_DQBLKSIZE),
        dq.dqb_bhardlimit.saturating_mul(QIF_DQBLKSIZE),
    )
}

fn quotactl_fd(fd: BorrowedFd<'_>, uid: u32) -> io::Result<UserQuota> {
    let cmd = libc::QCMD(libc::Q_GETQUOTA, libc::USRQUOTA);
    // SAFETY: an all-zero dqblk is valid.
    let mut dq: libc::dqblk = unsafe { std::mem::zeroed() };
    // SAFETY: quotactl_fd(fd, cmd, id, addr) with Q_GETQUOTA writes one dqblk to `addr`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            fd.as_raw_fd(),
            cmd,
            uid,
            &mut dq as *mut libc::dqblk,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(quota_from_dqblk(&dq))
}

fn quotactl_device(device: &Path, uid: u32) -> io::Result<UserQuota> {
    let cmd = libc::QCMD(libc::Q_GETQUOTA, libc::USRQUOTA);
    let cdev = CString::new(device.as_os_str().as_bytes())?;
    // SAFETY: an all-zero dqblk is valid.
    let mut dq: libc::dqblk = unsafe { std::mem::zeroed() };
    // SAFETY: quotactl with Q_GETQUOTA writes one dqblk to the last argument.
    let rc = unsafe {
        libc::quotactl(
            cmd,
            cdev.as_ptr(),
            uid as libc::c_int,
            &mut dq as *mut libc::dqblk as *mut libc::c_char,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(quota_from_dqblk(&dq))
}

/// One line of `/proc/self/mountinfo` or `/proc/self/mounts`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    /// Device number; not available in `/proc/self/mounts`.
    dev:         Option<u64>,
    mount_point: PathBuf,
    fstype:      String,
    source:      String,
    /// Superblock options (mountinfo) or all options (mounts).
    options:     String,
}

impl MountEntry {
    /// Device number from the entry, or from a `stat` of the mount point.
    fn device_number(&self) -> Option<u64> {
        self.dev
            .or_else(|| std::fs::metadata(&self.mount_point).ok().map(|meta| meta.dev()))
    }

    /// Paths that can be the block device of this mount, in order of preference.
    /// The source can be a name that is not a path (`/dev/root` is a common
    /// example), so `/dev/block/MAJOR:MINOR` is the alternative.
    fn device_candidates(&self) -> Vec<PathBuf> {
        let source = Some(PathBuf::from(&self.source)).filter(|source| source.is_absolute());
        let by_number = self
            .dev
            .map(|dev| PathBuf::from(format!("/dev/block/{}:{}", libc::major(dev), libc::minor(dev))));
        source.into_iter().chain(by_number).collect()
    }

    #[cfg(feature = "quota-nfs")]
    fn is_nfs(&self) -> bool {
        matches!(self.fstype.as_str(), "nfs" | "nfs4")
    }

    /// Value of a `name=value` mount option.
    #[cfg(feature = "quota-nfs")]
    fn option(&self, name: &str) -> Option<&str> {
        self.options
            .split(',')
            .find_map(|opt| opt.strip_prefix(name)?.strip_prefix('='))
    }
}

fn read_mounts() -> io::Result<Vec<MountEntry>> {
    match std::fs::read("/proc/self/mountinfo") {
        Ok(data) => Ok(parse_mountinfo(&data)),
        Err(err) => {
            debug!(
                "quota: cannot read /proc/self/mountinfo ({}), use /proc/self/mounts",
                err
            );
            std::fs::read("/proc/self/mounts").map(|data| parse_mounts(&data))
        },
    }
}

/// Find the mount of `path` (a canonical path) on device `dev`. Several mounts
/// can share one device (bind mounts, NFS mounts of one server filesystem),
/// thus prefer the longest mount point that contains `path`. On ties, the
/// last mount wins, because it is on top.
fn find_mount<'a>(mounts: &'a [MountEntry], dev: u64, path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|mount| mount.device_number() == Some(dev))
        .max_by_key(|mount| {
            (
                path.starts_with(&mount.mount_point),
                mount.mount_point.as_os_str().len(),
            )
        })
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&b| b == b' ')
        .filter(|field| !field.is_empty())
        .collect()
}

/// Parse `/proc/self/mountinfo`:
/// `id parent major:minor root mount_point options [optional...] - fstype source super_options`
fn parse_mountinfo(data: &[u8]) -> Vec<MountEntry> {
    data.split(|&b| b == b'\n')
        .filter_map(|line| {
            let fields = fields(line);
            // Optional fields start at index 6 and end with a "-" separator.
            let sep = 6 + fields.get(6..)?.iter().position(|&field| field == b"-")?;
            let (major, minor) = std::str::from_utf8(fields[2]).ok()?.split_once(':')?;
            let post = &fields[sep + 1..];
            Some(MountEntry {
                dev:         Some(libc::makedev(major.parse().ok()?, minor.parse().ok()?)),
                mount_point: PathBuf::from(unescape(fields[4])),
                fstype:      unescape_lossy(post.first()?),
                source:      unescape_lossy(post.get(1)?),
                options:     post.get(2).map_or_else(String::new, |opts| unescape_lossy(opts)),
            })
        })
        .collect()
}

/// Parse `/proc/self/mounts`: `source mount_point fstype options freq passno`
fn parse_mounts(data: &[u8]) -> Vec<MountEntry> {
    data.split(|&b| b == b'\n')
        .filter(|line| !line.starts_with(b"#"))
        .filter_map(|line| {
            let fields = fields(line);
            Some(MountEntry {
                dev:         None,
                mount_point: PathBuf::from(unescape(fields.get(1)?)),
                fstype:      unescape_lossy(fields.get(2)?),
                source:      unescape_lossy(fields.first()?),
                options:     fields
                    .get(3)
                    .map_or_else(String::new, |opts| unescape_lossy(opts)),
            })
        })
        .collect()
}

/// Decode the octal escapes of the kernel (`\040` for space, `\134` for backslash).
fn unescape(field: &[u8]) -> OsString {
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&first, tail)) = rest.split_first() {
        let octal = tail
            .get(..3)
            .filter(|digits| first == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)))
            .map(|digits| digits.iter().fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0')))
            .and_then(|value| u8::try_from(value).ok());
        match octal {
            Some(byte) => {
                out.push(byte);
                rest = &tail[3..];
            },
            None => {
                out.push(first);
                rest = tail;
            },
        }
    }
    OsString::from_vec(out)
}

fn unescape_lossy(field: &[u8]) -> String {
    unescape(field).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
25 22 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
30 22 8:3 / /home rw,relatime shared:2 master:7 - xfs /dev/sda3 rw,usrquota
31 22 8:3 /alice /srv/alice rw,relatime shared:2 - xfs /dev/sda3 rw,usrquota
32 22 8:4 / /mnt/my\\040disk rw - ext4 /dev/root rw
40 22 0:50 / /net/v6 rw - nfs [::1]:/export rw,vers=3,addr=::1
41 22 0:51 / /net/v4 rw - nfs4 server.example:/ rw,vers=4.2,addr=192.0.2.1

garbage line
50 22 0:60 / /broken rw shared:1 ext4 /dev/sdb1 rw
";

    fn mounts() -> Vec<MountEntry> {
        parse_mountinfo(MOUNTINFO.as_bytes())
    }

    fn dev(major: u32, minor: u32) -> u64 {
        libc::makedev(major, minor)
    }

    #[test]
    fn mountinfo_fields() {
        let mounts = mounts();
        // Empty lines, garbage, and lines without a separator are skipped.
        assert_eq!(mounts.len(), 7);
        assert_eq!(
            mounts[2],
            MountEntry {
                dev:         Some(dev(8, 3)),
                mount_point: PathBuf::from("/home"),
                fstype:      "xfs".into(),
                source:      "/dev/sda3".into(),
                options:     "rw,usrquota".into(),
            }
        );
    }

    #[test]
    fn mountinfo_unescape() {
        assert_eq!(mounts()[4].mount_point, Path::new("/mnt/my disk"));
        assert_eq!(unescape(b"a\\011b\\134c\\012"), OsString::from("a\tb\\c\n"));
        // Incomplete or invalid escapes stay as they are.
        assert_eq!(unescape(b"x\\04"), OsString::from("x\\04"));
        assert_eq!(unescape(b"x\\9999"), OsString::from("x\\9999"));
        assert_eq!(unescape(b"x\\777"), OsString::from("x\\777"));
        // Non-UTF-8 bytes are kept.
        assert_eq!(unescape(b"\\377").into_vec(), vec![0xff]);
    }

    #[test]
    fn mountinfo_nfs_sources() {
        let mounts = mounts();
        assert_eq!(mounts[5].source, "[::1]:/export");
        assert_eq!(mounts[5].fstype, "nfs");
        assert_eq!(mounts[6].source, "server.example:/");
        assert_eq!(mounts[6].fstype, "nfs4");
    }

    #[cfg(feature = "quota-nfs")]
    #[test]
    fn mount_options() {
        let mounts = mounts();
        assert_eq!(mounts[5].option("addr"), Some("::1"));
        assert_eq!(mounts[6].option("addr"), Some("192.0.2.1"));
        assert_eq!(mounts[6].option("vers"), Some("4.2"));
        assert_eq!(mounts[6].option("ad"), None);
        assert!(mounts[6].is_nfs());
        assert!(!mounts[0].is_nfs());
    }

    #[test]
    fn find_mount_longest_prefix() {
        let mounts = mounts();
        let home = find_mount(&mounts, dev(8, 3), Path::new("/home/bob")).unwrap();
        assert_eq!(home.mount_point, Path::new("/home"));
        let bind = find_mount(&mounts, dev(8, 3), Path::new("/srv/alice/docs")).unwrap();
        assert_eq!(bind.mount_point, Path::new("/srv/alice"));
        // Path is outside of all mount points of the device: use any of them.
        let any = find_mount(&mounts, dev(8, 3), Path::new("/elsewhere")).unwrap();
        assert_eq!(any.source, "/dev/sda3");
        // Prefix match is per path component.
        let root = find_mount(&mounts, dev(8, 2), Path::new("/homework")).unwrap();
        assert_eq!(root.mount_point, Path::new("/"));
        assert!(find_mount(&mounts, dev(9, 9), Path::new("/")).is_none());
    }

    #[test]
    fn device_candidates() {
        let mounts = mounts();
        assert_eq!(
            mounts[0].device_candidates(),
            vec![PathBuf::from("/dev/sda2"), PathBuf::from("/dev/block/8:2"),]
        );
        assert_eq!(
            mounts[4].device_candidates(),
            vec![PathBuf::from("/dev/root"), PathBuf::from("/dev/block/8:4"),]
        );
        // Not a path.
        assert_eq!(
            mounts[1].device_candidates(),
            vec![PathBuf::from("/dev/block/0:22")]
        );
    }

    #[test]
    fn mounts_fallback_format() {
        let data = b"# comment\n\n/dev/sda1 / ext4 rw,relatime 0 0\nhost:/a\\040b /mnt/x\\040y nfs rw,addr=10.0.0.1 0 0\nshort\n";
        let mounts = parse_mounts(data);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].dev, None);
        assert_eq!(mounts[0].source, "/dev/sda1");
        assert_eq!(mounts[1].source, "host:/a b");
        assert_eq!(mounts[1].mount_point, Path::new("/mnt/x y"));
        assert_eq!(mounts[1].fstype, "nfs");
        assert_eq!(mounts[1].options, "rw,addr=10.0.0.1");
    }

    #[test]
    fn real_mountinfo_contains_root() {
        let mounts = read_mounts().unwrap();
        assert!(mounts.iter().any(|mount| mount.mount_point == Path::new("/")));
    }

    #[test]
    fn dqblk_conversion() {
        // SAFETY: an all-zero dqblk is valid.
        let mut dq: libc::dqblk = unsafe { std::mem::zeroed() };
        dq.dqb_curspace = 5000;
        assert_eq!(
            quota_from_dqblk(&dq),
            UserQuota {
                used:  5000,
                limit: None,
            }
        );
        dq.dqb_bhardlimit = 10;
        assert_eq!(quota_from_dqblk(&dq).limit, Some(10 * 1024));
        dq.dqb_bsoftlimit = 8;
        assert_eq!(quota_from_dqblk(&dq).limit, Some(8 * 1024));
        dq.dqb_bsoftlimit = u64::MAX;
        assert_eq!(quota_from_dqblk(&dq).limit, Some(u64::MAX));
    }
}
