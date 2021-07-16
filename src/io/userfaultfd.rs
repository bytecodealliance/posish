//! The Linux `userfaultfd` API.
//!
//! # Safety
//!
//! Calling `userfaultfd` is safe, but the returned file descriptor lets users
//! observe and manipulate process memory in magical ways.
#![allow(unsafe_code)]

use crate::{imp, io};
use io_lifetimes::OwnedFd;

pub use imp::io::UserfaultfdFlags;

/// `userfaultfd(flags)`
///
/// # Safety
///
/// The call itself is safe, but the returned file descriptor lets users
/// observe and manipuate process memory in magical ways.
///
/// # References
///  - [Linux]
///
/// [Linux]: https://man7.org/linux/man-pages/man2/userfaultfd.2.html
#[inline]
pub unsafe fn userfaultfd(flags: UserfaultfdFlags) -> io::Result<OwnedFd> {
    imp::syscalls::userfaultfd(flags)
}
