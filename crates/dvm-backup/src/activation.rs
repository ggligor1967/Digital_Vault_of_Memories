//! Publish without replacing an existing destination.
use std::{io, path::Path};

#[cfg(windows)]
pub(crate) fn activate_file_noreplace(staging: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let from: Vec<u16> = staging.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // Flags=0 omits MOVEFILE_REPLACE_EXISTING and MOVEFILE_COPY_ALLOWED.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn activate_directory_noreplace(staging: &Path, destination: &Path) -> io::Result<()> {
    activate_file_noreplace(staging, destination)
}

#[cfg(not(windows))]
pub(crate) fn activate_file_noreplace(staging: &Path, destination: &Path) -> io::Result<()> {
    std::fs::hard_link(staging, destination)?;
    std::fs::remove_file(staging)
}

#[cfg(not(windows))]
pub(crate) fn activate_directory_noreplace(staging: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists));
    }
    std::fs::rename(staging, destination)
}
