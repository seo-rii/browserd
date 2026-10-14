#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use browserd_sandbox::{
    SANDBOX_SCRATCH_MAX_BYTES, SANDBOX_SCRATCH_PATH, validate_scratch_directory,
};

#[test]
fn scratch_constants_are_a_fixed_private_path_and_physical_limit() {
    assert_eq!(SANDBOX_SCRATCH_PATH, "/profile/browserd-files");
    assert_eq!(SANDBOX_SCRATCH_MAX_BYTES, 32 * 1024 * 1024);
}

#[test]
fn scratch_rejects_non_directory_and_unbounded_filesystems() {
    assert!(validate_scratch_directory(&OwnedFd::from(File::open("/dev/null").unwrap())).is_err());
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(directory.path())
        .unwrap();
    assert!(
        validate_scratch_directory(&OwnedFd::from(fd)).is_err(),
        "ordinary host filesystem is not an authenticated bounded scratch mount"
    );
}

#[test]
fn scratch_rejects_a_public_tmpfs_directory() {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open("/dev/shm")
        .unwrap();
    assert!(validate_scratch_directory(&OwnedFd::from(directory)).is_err());
}

#[test]
#[ignore = "requires a Linux user/mount namespace and tmpfs mount support"]
fn private_tmpfs_capability_enforces_a_physical_byte_limit() {
    if std::env::var_os("BROWSERD_SCRATCH_MOUNT_HELPER").is_none() {
        let output = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--fork"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "private_tmpfs_capability_enforces_a_physical_byte_limit",
                "--nocapture",
            ])
            .env("BROWSERD_SCRATCH_MOUNT_HELPER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated tmpfs proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use nix::mount::{MsFlags, mount, umount};
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    mount(
        Some("tmpfs"),
        directory.path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=33554432,mode=0700"),
    )
    .unwrap();
    let fd = OwnedFd::from(File::open(directory.path()).unwrap());
    validate_scratch_directory(&fd).expect("private bounded tmpfs should qualify");
    let mut output = File::create(directory.path().join("bounded-data")).unwrap();
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..32 {
        output.write_all(&chunk).unwrap();
    }
    assert_eq!(
        output.write_all(&[1]).unwrap_err().raw_os_error(),
        Some(nix::libc::ENOSPC)
    );
    drop(output);
    drop(fd);
    umount(directory.path()).unwrap();
}
