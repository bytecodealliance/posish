//! Utilities for working with `/proc`, where Linux's `procfs` is typically
//! mounted. `/proc` serves as an adjunct to Linux's main syscall surface area,
//! providing additional features with an awkward interface.
//!
//! This module does a considerable amount of work to determine whether `/proc`
//! is mounted, with actual `procfs`, and without any additional mount points
//! on top of the paths we open.

use crate::{
    fs::{cwd, fstat, fstatfs, major, openat, renameat, Mode, OFlags, Stat, PROC_SUPER_MAGIC},
    io::{self, OwnedFd},
    path::DecInt,
    process::{getgid, getpid, getuid},
};
use cstr::cstr;
use io_lifetimes::{AsFd, BorrowedFd};
use once_cell::sync::Lazy;

/// Linux's procfs always uses inode 1 for its root directory.
const PROC_ROOT_INO: u64 = 1;

// Identify an entry within "/proc", to determine which anomalies to
// check for.
enum Kind {
    Proc,
    Pid,
    Fd,
    #[cfg(linux_raw)]
    File,
}

/// Check a subdirectory of "/proc" for anomalies.
fn check_proc_entry(
    kind: Kind,
    entry: BorrowedFd<'_>,
    proc_stat: Option<&Stat>,
    uid: u32,
    gid: u32,
) -> io::Result<Stat> {
    // Check the filesystem magic.
    check_procfs(entry)?;

    let stat = fstat(&entry)?;

    match kind {
        Kind::Proc => check_proc_root(entry, &stat)?,
        Kind::Pid | Kind::Fd => check_proc_subdir(entry, &stat, proc_stat)?,
        #[cfg(linux_raw)]
        Kind::File => check_proc_file(&stat, proc_stat)?,
    }

    // Check the ownership of the directory.
    if (stat.st_uid, stat.st_gid) != (uid, gid) {
        return Err(io::Error::NOTSUP);
    }

    // "/proc" directories are typically mounted r-xr-xr-x.
    // "/proc/self/fd" is r-x------. Allow them to have fewer permissions, but
    // not more.
    let expected_mode = if let Kind::Fd = kind { 0o500 } else { 0o555 };
    if stat.st_mode & 0o777 & !expected_mode != 0 {
        return Err(io::Error::NOTSUP);
    }

    match kind {
        Kind::Fd => {
            // Check that the "/proc/self/fd" directory doesn't have any extraneous
            // links into it (which might include unexpected subdirectories).
            if stat.st_nlink != 2 {
                return Err(io::Error::NOTSUP);
            }
        }
        Kind::Pid | Kind::Proc => {
            // Check that the "/proc" and "/proc/self" directories aren't empty.
            if stat.st_nlink <= 2 {
                return Err(io::Error::NOTSUP);
            }
        }
        #[cfg(linux_raw)]
        Kind::File => {
            // Check that files in procfs don't have extraneous hard links to
            // them (which might indicate hard links to other things).
            if stat.st_nlink != 1 {
                return Err(io::Error::NOTSUP);
            }
        }
    }

    Ok(stat)
}

fn check_proc_root(entry: BorrowedFd<'_>, stat: &Stat) -> io::Result<()> {
    // We use `O_DIRECTORY` for proc directories, so open should fail if we
    // don't get a directory when we expect one.
    assert_eq!(stat.st_mode & Mode::IFMT.bits(), Mode::IFDIR.bits());

    // Check the root inode number.
    if stat.st_ino != PROC_ROOT_INO {
        return Err(io::Error::NOTSUP);
    }

    // Proc is a non-device filesystem, so check for major number 0.
    // <https://www.kernel.org/doc/Documentation/admin-guide/devices.txt>
    if major(stat.st_dev) != 0 {
        return Err(io::Error::NOTSUP);
    }

    // Check that "/proc" is a mountpoint.
    if !is_mountpoint(entry)? {
        return Err(io::Error::NOTSUP);
    }

    Ok(())
}

fn check_proc_subdir(
    entry: BorrowedFd<'_>,
    stat: &Stat,
    proc_stat: Option<&Stat>,
) -> io::Result<()> {
    // We use `O_DIRECTORY` for proc directories, so open should fail if we
    // don't get a directory when we expect one.
    assert_eq!(stat.st_mode & Mode::IFMT.bits(), Mode::IFDIR.bits());

    check_proc_nonroot(stat, proc_stat)?;

    // Check that subdirectories of "/proc" are not mount points.
    if is_mountpoint(entry)? {
        return Err(io::Error::NOTSUP);
    }

    Ok(())
}

#[cfg(linux_raw)]
fn check_proc_file(stat: &Stat, proc_stat: Option<&Stat>) -> io::Result<()> {
    // Check that we have a regular file.
    if stat.st_mode & Mode::IFMT.bits() != Mode::IFREG.bits() {
        return Err(io::Error::NOTSUP);
    }

    check_proc_nonroot(stat, proc_stat)?;

    Ok(())
}

fn check_proc_nonroot(stat: &Stat, proc_stat: Option<&Stat>) -> io::Result<()> {
    // Check that we haven't been linked back to the root of "/proc".
    if stat.st_ino == PROC_ROOT_INO {
        return Err(io::Error::NOTSUP);
    }

    // Check that we're still in procfs.
    if stat.st_dev != proc_stat.unwrap().st_dev {
        return Err(io::Error::NOTSUP);
    }

    Ok(())
}

/// Check that `file` is opened on a `procfs` filesystem.
fn check_procfs(file: BorrowedFd<'_>) -> io::Result<()> {
    let statfs = fstatfs(&file)?;
    let f_type = statfs.f_type;
    if f_type != PROC_SUPER_MAGIC {
        return Err(io::Error::NOTSUP);
    }

    Ok(())
}

/// Check whether the given directory handle is a mount point. We use a
/// `rename` call that would otherwise fail, but which fails with `EXDEV`
/// first if it would cross a mount point.
fn is_mountpoint(file: BorrowedFd<'_>) -> io::Result<bool> {
    let err = renameat(&file, cstr!("../."), &file, cstr!(".")).unwrap_err();
    match err {
        io::Error::XDEV => Ok(true), // the rename failed due to crossing a mount point
        io::Error::BUSY => Ok(false), // the rename failed normally
        _ => panic!("Unexpected error from `renameat`: {:?}", err),
    }
}

/// Returns a handle to Linux's `/proc` directory.
///
/// This ensures that `/proc` is procfs, that nothing is mounted on top of it,
/// and that it looks normal. It also returns the `Stat` of `/proc`.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man5/proc.5.html
pub fn proc() -> io::Result<(BorrowedFd<'static>, &'static Stat)> {
    #[allow(clippy::useless_conversion)]
    static PROC: Lazy<io::Result<(OwnedFd, Stat)>> = Lazy::new(|| {
        let oflags = OFlags::NOFOLLOW
            | OFlags::PATH
            | OFlags::DIRECTORY
            | OFlags::CLOEXEC
            | OFlags::NOCTTY
            | OFlags::NOATIME;
        let proc: OwnedFd = openat(&cwd(), cstr!("/proc"), oflags, Mode::empty())?.into();
        let proc_stat = check_proc_entry(Kind::Proc, proc.as_fd(), None, 0, 0)?;

        Ok((proc, proc_stat))
    });

    PROC.as_ref()
        .map(|(fd, stat)| (fd.as_fd(), stat))
        .map_err(|_err| io::Error::NOTSUP)
}

/// Returns a handle to Linux's `/proc/self` directory.
///
/// This ensures that `/proc/self` is procfs, that nothing is mounted on top of
/// it, and that it looks normal. It also returns the `Stat` of `/proc/self`.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man5/proc.5.html
pub fn proc_self() -> io::Result<(BorrowedFd<'static>, &'static Stat)> {
    #[allow(clippy::useless_conversion)]
    static PROC_SELF: Lazy<io::Result<(OwnedFd, Stat)>> = Lazy::new(|| {
        let (proc, proc_stat) = proc()?;

        let (uid, gid, pid) = (getuid(), getgid(), getpid());
        let oflags = OFlags::NOFOLLOW
            | OFlags::PATH
            | OFlags::DIRECTORY
            | OFlags::CLOEXEC
            | OFlags::NOCTTY
            | OFlags::NOATIME;

        // Open "/proc/self". Use our pid to compute the name rather than literally
        // using "self", as "self" is a symlink.
        let proc_self: OwnedFd = openat(&proc, DecInt::new(pid), oflags, Mode::empty())?.into();
        let proc_self_stat =
            check_proc_entry(Kind::Pid, proc_self.as_fd(), Some(proc_stat), uid, gid)?;

        Ok((proc_self, proc_self_stat))
    });

    PROC_SELF
        .as_ref()
        .map(|(owned, stat)| (owned.as_fd(), stat))
        .map_err(|_err| io::Error::NOTSUP)
}

/// Returns a handle to Linux's `/proc/self/fd` directory.
///
/// This ensures that `/proc/self/fd` is `procfs`, that nothing is mounted on
/// top of it, and that it looks normal. It also returns the `Stat` of
/// `/proc/self/fd`.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man5/proc.5.html
pub fn proc_self_fd() -> io::Result<(BorrowedFd<'static>, &'static Stat)> {
    #[allow(clippy::useless_conversion)]
    static PROC_SELF_FD: Lazy<io::Result<(OwnedFd, Stat)>> = Lazy::new(|| {
        let (_, proc_stat) = proc()?;

        let (proc_self, proc_self_stat) = proc_self()?;
        let oflags = OFlags::NOFOLLOW
            | OFlags::PATH
            | OFlags::DIRECTORY
            | OFlags::CLOEXEC
            | OFlags::NOCTTY
            | OFlags::NOATIME;

        // Open "/proc/self/fd".
        let proc_self_fd: OwnedFd = openat(&proc_self, cstr!("fd"), oflags, Mode::empty())?.into();
        let proc_self_fd_stat = check_proc_entry(
            Kind::Fd,
            proc_self_fd.as_fd(),
            Some(proc_stat),
            proc_self_stat.st_uid,
            proc_self_stat.st_gid,
        )?;

        Ok((proc_self_fd, proc_self_fd_stat))
    });

    PROC_SELF_FD
        .as_ref()
        .map(|(owned, stat)| (owned.as_fd(), stat))
        .map_err(|_err| io::Error::NOTSUP)
}

/// Returns a handle to Linux's `/proc/self/auxv` file.
///
/// This ensures that `/proc/self/auxv` is `procfs`, that nothing is mounted on
/// top of it, and that it looks normal.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man5/proc.5.html
#[cfg(linux_raw)]
pub(crate) fn proc_self_auxv() -> io::Result<OwnedFd> {
    let (_, proc_stat) = proc()?;
    let (proc_self, proc_self_stat) = proc_self()?;

    let oflags =
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NOATIME;
    let auxv: OwnedFd = openat(&proc_self, cstr!("auxv"), oflags, Mode::empty())?.into();

    let _ = check_proc_entry(
        Kind::File,
        auxv.as_fd(),
        Some(proc_stat),
        proc_self_stat.st_uid,
        proc_self_stat.st_gid,
    )?;

    Ok(auxv)
}
