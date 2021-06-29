use crate::{io, path::DecInt};
#[cfg(target_os = "hermit")]
use std::os::hermit::ext::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "vxworks")]
use std::os::vxworks::ext::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "wasi")]
use std::os::wasi::ffi::{OsStrExt, OsStringExt};
use std::{
    borrow::Cow,
    ffi::{CStr, CString, OsStr, OsString},
    path::{Component, Components, Iter, Path, PathBuf},
    str,
};

/// A trait for passing path arguments.
///
/// This is similar to [`AsRef`]`<`[`Path`]`>`, but is implemented for more
/// kinds of strings and can convert into more kinds of strings.
///
/// # Example
///
/// ```rust
/// use posish::{io, path::Arg};
/// use std::ffi::CStr;
///
/// pub fn touch<P: Arg>(path: P) -> io::Result<()> {
///     let path = path.into_c_str()?;
///     _touch(&path)
/// }
///
/// fn _touch(path: &CStr) -> io::Result<()> {
///     // implementation goes here
///     Ok(())
/// }
/// ```
///
/// Users can then call `touch("foo")`, `touch(cstr!("foo"))`,
/// `touch(Path::new("foo"))`, or many other things.
///
/// [`AsRef`]: std::convert::AsRef
pub trait Arg {
    /// Return a view of this string as a string slice.
    fn as_str(&self) -> io::Result<&str>;

    /// Return a potentially-lossy rendering of this string as a `Cow<str>`.
    fn to_string_lossy(&self) -> Cow<str>;

    /// Return a view of this string as a maybe-owned [`CStr`].
    #[cfg(not(windows))]
    fn as_c_str(&self) -> io::Result<Cow<CStr>>;

    /// Consume `self` and return a view of this string as a maybe-owned
    /// [`CStr`].
    #[cfg(not(windows))]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b;

    /// Return a view of this string as a byte slice.
    #[cfg(not(windows))]
    fn as_maybe_utf8_bytes(&self) -> &[u8];

    /// Return a view of this string as a maybe-owned [`OsStr`].
    #[cfg(windows)]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>>;

    /// Run a closure with `self` passed in as a `&CStr`.
    #[cfg(not(windows))]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>;
}

impl Arg for &str {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        Ok(self)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl Arg for &String {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        Ok(self)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(String::as_str(self).as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        self.as_str().into_c_str()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl Arg for String {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        Ok(self)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(&CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?)
    }
}

impl Arg for &OsStr {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        OsStr::to_string_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl Arg for &OsString {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        OsString::as_os_str(self).to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_os_str().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(OsString::as_os_str(self).as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        self.as_os_str().into_c_str()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl Arg for OsString {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_os_str().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_os_str().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.into_vec()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(&CString::new(self.into_vec()).map_err(|_cstr_err| io::Error::INVAL)?)
    }
}

impl Arg for &Path {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_os_str().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Path::to_string_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_os_str().as_bytes(), f)
    }
}

impl Arg for &PathBuf {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        PathBuf::as_path(self)
            .as_os_str()
            .to_str()
            .ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_path().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(PathBuf::as_path(self).as_os_str().as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        self.as_path().into_c_str()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        PathBuf::as_path(self).as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_os_str().as_bytes(), f)
    }
}

impl Arg for PathBuf {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_os_str().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_os_str().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.into_os_string().into_vec()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(
            &CString::new(self.into_os_string().into_vec())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        )
    }
}

impl Arg for &CStr {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.to_str().map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        CStr::to_string_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Borrowed(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Borrowed(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.to_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(self)
    }
}

impl Arg for &CString {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        CString::as_c_str(self)
            .to_str()
            .map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        CString::as_c_str(self).to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Borrowed(CString::as_c_str(self)))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Borrowed(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.to_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(self)
    }
}

impl Arg for CString {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.to_str().map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_c_str().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Borrowed(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(&self)
    }
}

impl<'a> Arg for Cow<'a, str> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        Ok(self)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_ref()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            match self {
                Cow::Owned(s) => CString::new(s),
                Cow::Borrowed(s) => CString::new(s),
            }
            .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl<'a> Arg for Cow<'a, OsStr> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        (**self).to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        (**self).to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            match self {
                Cow::Owned(os) => CString::new(os.into_vec()),
                Cow::Borrowed(os) => CString::new(os.as_bytes()),
            }
            .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_bytes(), f)
    }
}

impl<'a> Arg for Cow<'a, CStr> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.to_str().map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        let borrow: &CStr = std::borrow::Borrow::borrow(self);
        borrow.to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Borrowed(self))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.to_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(&self)
    }
}

impl<'a> Arg for Component<'a> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_os_str().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_os_str().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_os_str().as_bytes(), f)
    }
}

impl<'a> Arg for Components<'a> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_path().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_path().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_path().as_os_str().as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_path().as_os_str().as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_path().as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_path().as_os_str().as_bytes(), f)
    }
}

impl<'a> Arg for Iter<'a> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_path().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        self.as_path().to_string_lossy()
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_path().as_os_str().as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_path().as_os_str().as_bytes())
                .map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_path().as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_path().as_os_str().as_bytes(), f)
    }
}

impl Arg for &[u8] {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        str::from_utf8(self).map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(*self).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self, f)
    }
}

impl Arg for &Vec<u8> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        str::from_utf8(self).map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_slice()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_slice()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self, f)
    }
}

impl Arg for Vec<u8> {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        str::from_utf8(self).map_err(|_utf8_err| io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_slice()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        f(&CString::new(self).map_err(|_cstr_err| io::Error::INVAL)?)
    }
}

impl Arg for DecInt {
    #[inline]
    fn as_str(&self) -> io::Result<&str> {
        self.as_os_str().to_str().ok_or(io::Error::INVAL)
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        Path::to_string_lossy(self)
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_c_str(&self) -> io::Result<Cow<CStr>> {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_c_str<'b>(self) -> io::Result<Cow<'b, CStr>>
    where
        Self: 'b,
    {
        Ok(Cow::Owned(
            CString::new(self.as_os_str().as_bytes()).map_err(|_cstr_err| io::Error::INVAL)?,
        ))
    }

    #[cfg(not(windows))]
    #[inline]
    fn as_maybe_utf8_bytes(&self) -> &[u8] {
        self.as_os_str().as_bytes()
    }

    #[cfg(windows)]
    #[inline]
    fn as_os_str(&self) -> io::Result<Cow<OsStr>> {
        self.as_ref()
    }

    #[cfg(not(windows))]
    #[inline]
    fn into_with_c_str<T, F>(self, f: F) -> io::Result<T>
    where
        Self: Sized,
        F: FnOnce(&CStr) -> io::Result<T>,
    {
        with_c_str(self.as_os_str().as_bytes(), f)
    }
}

/// Run a closure with `bytes` passed in as a `&CStr`.
#[inline]
fn with_c_str<T, F>(bytes: &[u8], f: F) -> io::Result<T>
where
    F: FnOnce(&CStr) -> io::Result<T>,
{
    // Most paths are less than this long. The rest can go through the dynamic
    // allocation path. If you're opening many files in a directory with a long
    // path, consider opening the directory and using openat to open the files
    // under it, which will avoid this, and is often faster in the OS as well.
    const SIZE: usize = 256;
    // Test with >= so that we have room for the trailing NUL.
    if bytes.len() >= SIZE {
        return with_c_str_slow_path(bytes, f);
    }
    let mut buffer: [u8; SIZE] = [0u8; SIZE];
    // Copy the bytes in; the buffer already has zeros for the trailing NUL.
    buffer[..bytes.len()].copy_from_slice(bytes);
    f(CStr::from_bytes_with_nul(&buffer[..=bytes.len()]).map_err(|_cstr_err| io::Error::INVAL)?)
}

/// The slow path which handles any length. In theory OS's only support up
/// to `PATH_MAX`, but we let the OS enforce that.
#[cold]
fn with_c_str_slow_path<T, F>(bytes: &[u8], f: F) -> io::Result<T>
where
    F: FnOnce(&CStr) -> io::Result<T>,
{
    f(&CString::new(bytes).map_err(|_cstr_err| io::Error::INVAL)?)
}

#[test]
fn test_arg() {
    use cstr::cstr;
    use std::borrow::Borrow;

    let t: &str = "hello";
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: String = "hello".to_owned();
    assert_eq!("hello", Arg::as_str(&t).unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: &OsStr = OsStr::new("hello");
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: OsString = OsString::from("hello".to_owned());
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: &Path = Path::new("hello");
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: PathBuf = PathBuf::from("hello".to_owned());
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: &CStr = cstr!("hello");
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: CString = cstr!("hello").to_owned();
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&Arg::as_c_str(&t).unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Components = Path::new("hello").components();
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Component = Path::new("hello").components().next().unwrap();
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Iter = Path::new("hello").iter();
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<str> = Cow::Borrowed("hello");
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<str> = Cow::Owned("hello".to_owned());
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<OsStr> = Cow::Borrowed(OsStr::new("hello"));
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<OsStr> = Cow::Owned(OsString::from("hello".to_owned()));
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<CStr> = Cow::Borrowed(cstr!("hello"));
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Cow<CStr> = Cow::Owned(cstr!("hello").to_owned());
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: &[u8] = b"hello";
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.into_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: Vec<u8> = b"hello".to_vec();
    assert_eq!("hello", t.as_str().unwrap());
    assert_eq!("hello".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("hello"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("hello"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _],
        t.as_os_str()
    );

    let t: DecInt = DecInt::new(43110);
    assert_eq!("43110", t.as_str().unwrap());
    assert_eq!("43110".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(cstr!("43110"), Borrow::borrow(&t.as_c_str().unwrap()));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!("43110"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"43110", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &['4' as u16, '3' as _, '1' as _, '1' as _, 'o' as _],
        t.as_os_str()
    );
}

#[test]
fn test_invalid() {
    use cstr::cstr;
    use std::borrow::Borrow;

    let t: &[u8] = b"hello\xc0world";
    assert_eq!(t.as_str().unwrap_err(), io::Error::INVAL);
    assert_eq!("hello\u{fffd}world".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(
        cstr!(b"hello\xc0world"),
        Borrow::borrow(&t.as_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(
        cstr!(b"hello\xc0world"),
        Borrow::borrow(&t.clone().into_c_str().unwrap())
    );
    #[cfg(not(windows))]
    assert_eq!(b"hello\xc0world", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &[
            'h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _, 0xc0, 'w' as _, 'o' as _, 'r' as _,
            'l' as _, 'd' as _
        ],
        t.as_os_str()
    );
}

#[test]
fn test_embedded_nul() {
    let t: &[u8] = b"hello\0world";
    assert_eq!("hello\0world", t.as_str().unwrap());
    assert_eq!("hello\0world".to_owned(), Arg::to_string_lossy(&t));
    #[cfg(not(windows))]
    assert_eq!(t.as_c_str().unwrap_err(), io::Error::INVAL);
    #[cfg(not(windows))]
    assert_eq!(t.clone().into_c_str().unwrap_err(), io::Error::INVAL);
    #[cfg(not(windows))]
    assert_eq!(b"hello\0world", t.as_maybe_utf8_bytes());
    #[cfg(windows)]
    assert_eq!(
        &[
            'h' as u16, 'e' as _, 'l' as _, 'l' as _, 'o' as _, 0, 'w' as _, 'o' as _, 'r' as _,
            'l' as _, 'd' as _
        ],
        t.as_os_str()
    );
}
