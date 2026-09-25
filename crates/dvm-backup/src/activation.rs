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

#[cfg(target_os = "linux")]
pub(crate) fn activate_directory_noreplace(staging: &Path, destination: &Path) -> io::Result<()> {
    activate_directory_noreplace_with_publish_hook(staging, destination, || {})
}

#[cfg(target_os = "linux")]
fn activate_directory_noreplace_with_publish_hook(
    staging: &Path,
    destination: &Path,
    before_publish: impl FnOnce(),
) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    before_publish();
    renameat_with(CWD, staging, CWD, destination, RenameFlags::NOREPLACE).map_err(Into::into)
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub(crate) fn activate_directory_noreplace(_: &Path, _: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory activation is unavailable on this target",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::symlink,
        sync::{Arc, Barrier},
        thread,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> io::Result<Self> {
            let root =
                std::env::temp_dir().join(format!("dvm-activation-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root)?;
            Ok(Self(root))
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn existing_directories_preserve_staging_and_destination() -> TestResult {
        for occupied in [false, true] {
            let root = TestRoot::new()?;
            let staging = root.path("staging");
            let destination = root.path("destination");
            std::fs::create_dir(&staging)?;
            std::fs::create_dir(&destination)?;
            if occupied {
                std::fs::write(destination.join("sentinel"), b"competitor")?;
            }

            let error = activate_directory_noreplace(&staging, &destination).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert!(staging.is_dir());
            assert!(destination.is_dir());
            assert_eq!(destination.join("sentinel").exists(), occupied);
            if occupied {
                assert_eq!(std::fs::read(destination.join("sentinel"))?, b"competitor");
            }
        }
        println!("RESTORE_NOREPLACE_EXISTING_DIR=PASS");
        Ok(())
    }

    #[test]
    fn dangling_symlink_is_never_replaced() -> TestResult {
        let root = TestRoot::new()?;
        let staging = root.path("staging");
        let destination = root.path("destination");
        let missing_target = root.path("missing");
        std::fs::create_dir(&staging)?;
        symlink(&missing_target, &destination)?;

        let error = activate_directory_noreplace(&staging, &destination).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(staging.is_dir());
        assert_eq!(std::fs::read_link(&destination)?, missing_target);
        println!("RESTORE_NOREPLACE_DANGLING_SYMLINK=PASS");
        Ok(())
    }

    #[test]
    fn competitor_at_publish_boundary_wins_without_replacement() -> TestResult {
        let root = TestRoot::new()?;
        let staging = root.path("staging");
        let destination = root.path("destination");
        std::fs::create_dir(&staging)?;
        let rendezvous = Arc::new(Barrier::new(2));
        let competitor_barrier = Arc::clone(&rendezvous);
        let competitor_destination = destination.clone();
        let competitor = thread::spawn(move || {
            competitor_barrier.wait();
            std::fs::create_dir(&competitor_destination)
        });

        let error = activate_directory_noreplace_with_publish_hook(&staging, &destination, || {
            rendezvous.wait();
            assert!(matches!(competitor.join(), Ok(Ok(()))));
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(staging.is_dir());
        assert!(destination.is_dir());
        assert_eq!(std::fs::read_dir(&destination)?.count(), 0);
        println!("RESTORE_NOREPLACE_RACE=PASS");
        Ok(())
    }

    #[test]
    fn backup_file_activation_preserves_existing_destination() -> TestResult {
        let root = TestRoot::new()?;
        let staging = root.path("backup.part");
        let destination = root.path("backup.dvmbak");
        std::fs::write(&staging, b"staged")?;
        std::fs::write(&destination, b"original")?;
        assert_eq!(
            activate_file_noreplace(&staging, &destination)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&staging)?, b"staged");
        assert_eq!(std::fs::read(&destination)?, b"original");
        std::fs::remove_file(&destination)?;
        activate_file_noreplace(&staging, &destination)?;
        assert!(!staging.exists());
        assert_eq!(std::fs::read(&destination)?, b"staged");
        println!("BACKUP_NOREPLACE_REGRESSION=PASS");
        Ok(())
    }
}
