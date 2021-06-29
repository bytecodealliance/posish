//! Automatically enable "large file" support features.

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
)))]
pub(super) use libc::{
    fstat as libc_fstat, fstatat as libc_fstatat, lseek as libc_lseek, off_t as libc_off_t,
};

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
))]
pub(super) use libc::{
    fstat64 as libc_fstat, fstatat64 as libc_fstatat, lseek64 as libc_lseek, off64_t as libc_off_t,
};

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
    target_os = "wasi",
)))]
pub(super) use libc::mmap as libc_mmap;

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
))]
pub(super) use libc::mmap64 as libc_mmap;

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
    target_os = "redox",
)))]
pub(super) use libc::openat as libc_openat;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
))]
pub(super) use libc::openat64 as libc_openat;

#[cfg(target_os = "fuchsia")]
pub(super) use libc::fallocate as libc_fallocate;
#[cfg(any(target_os = "android", target_os = "linux",))]
pub(super) use libc::fallocate64 as libc_fallocate;
#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox",
)))]
pub(super) use libc::posix_fadvise as libc_posix_fadvise;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
))]
pub(super) use libc::posix_fadvise64 as libc_posix_fadvise;

#[cfg(all(not(any(target_os = "android", target_os = "linux", target_os = "emscripten"))))]
pub(super) use libc::{pread as libc_pread, pwrite as libc_pwrite};
#[cfg(any(target_os = "android", target_os = "linux", target_os = "emscripten"))]
pub(super) use libc::{
    pread64 as libc_pread, preadv64 as libc_preadv, pwrite64 as libc_pwrite,
    pwritev64 as libc_pwritev,
};
#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "redox"
)))]
pub(super) use libc::{preadv as libc_preadv, pwritev as libc_pwritev};
// `preadv64v2`/`pwritev64v2` submitted upstream here:
// <https://github.com/rust-lang/libc/pull/2257>
#[cfg(all(target_pointer_width = "64", target_os = "linux", target_env = "gnu"))]
pub(super) use libc::{preadv2 as libc_preadv2, pwritev2 as libc_pwritev2};

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
    target_os = "netbsd",
    target_os = "redox",
    target_os = "wasi"
)))]
pub(super) use libc::fstatfs as libc_fstatfs;
#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "l4re",
    target_os = "fuchsia",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "redox",
)))]
pub(super) use libc::posix_fallocate as libc_posix_fallocate;
#[cfg(any(target_os = "l4re",))]
pub(super) use libc::posix_fallocate64 as libc_posix_fallocate;

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "emscripten",
    target_os = "l4re",
))]
pub(super) use libc::fstatfs64 as libc_fstatfs;
