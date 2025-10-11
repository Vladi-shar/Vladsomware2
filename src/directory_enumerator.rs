use std::{
    cmp::Eq,
    ffi::{OsStr, OsString},
    hash::{Hash, Hasher},
    os::windows::ffi::{OsStrExt, OsStringExt},
};
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{GetLastError, ERROR_NO_MORE_FILES, HANDLE},
        Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW},
    },
};

struct FindHandle(HANDLE);
impl Drop for FindHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.0);
        };
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FindData(pub WIN32_FIND_DATAW);

#[derive(PartialEq, Eq, Hash)]
struct FindKey {
    file_size: u64,
    file_name: OsString,
}

impl From<&WIN32_FIND_DATAW> for FindKey {
    fn from(fd: &WIN32_FIND_DATAW) -> Self {
        Self {
            file_size: ((fd.nFileSizeHigh as u64) << 32) | fd.nFileSizeLow as u64,
            file_name: name_from_win32_find_data(fd),
        }
    }
}
impl PartialEq for FindData {
fn eq(&self, other: &Self) -> bool {
    FindKey::from(&self.0) == FindKey::from(&other.0)
}
}
impl Eq for FindData {}

impl Hash for FindData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        FindKey::from(&self.0).hash(state)
    }
}

pub fn enumerate_dir_entries<P, F>(pattern: P, mut cb: F) -> windows::core::Result<()>
where
    P: AsRef<OsStr>,
    F: FnMut(&FindData),
{
    unsafe {
        let mut fd: WIN32_FIND_DATAW = std::mem::zeroed();
        let wide: Vec<u16> = pattern
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h_find = FindFirstFileW(PCWSTR(wide.as_ptr()), &mut fd as *mut _).map_err(|e| e)?;
        let _h_find = FindHandle(h_find);
        loop {
            cb(&FindData(fd));
            if FindNextFileW(_h_find.0, &mut fd as *mut _).is_err() {
                break;
            }
        }
        let le = GetLastError();
        if le != ERROR_NO_MORE_FILES {
            Err(Error::from(le))
        } else {
            Ok(())
        }
    }
}

pub fn name_from_win32_find_data(fd: &WIN32_FIND_DATAW) -> OsString {
    let len = fd
        .cFileName
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fd.cFileName.len());
    OsString::from_wide(&fd.cFileName[..len])
}

pub fn name_from_find_data(fd: &FindData) -> OsString {
    name_from_win32_find_data(&fd.0)
}
