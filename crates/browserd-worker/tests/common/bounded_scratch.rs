//! Private physical tmpfs fixture for unqualified browser file behavior tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs;
use std::path::Path;

/// Prepare an entirely private root so the production constant /profile/browserd-files is real.
/// The outer process owns the empty mountpoint and removes it only after this namespace exits.
fn isolate_filesystem(root: &Path) {
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    assert_ne!(uid, 0, "Chromium must run as the real non-root test uid");
    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size=16777216,mode=0700,uid={uid},gid={gid}").as_str()),
    )
    .unwrap();
    for name in ["usr", "lib", "lib64", "bin", "etc", "home", "tmp"] {
        let source = Path::new("/").join(name);
        if !source.exists() {
            continue;
        }
        let destination = root.join(name);
        fs::create_dir(&destination).unwrap();
        mount(
            Some(source.as_path()),
            &destination,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        if name != "tmp" {
            mount(
                None::<&str>,
                &destination,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .unwrap();
        }
    }
    for name in [
        "proc",
        "dev",
        "dev/shm",
        "profile",
        "profile/browserd-files",
    ] {
        fs::create_dir(root.join(name)).unwrap();
    }
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .unwrap();
    for name in ["null", "zero", "random", "urandom"] {
        let destination = root.join("dev").join(name);
        fs::File::create(&destination).unwrap();
        mount(
            Some(Path::new("/dev").join(name).as_path()),
            &destination,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
    }
    mount(
        Some("tmpfs"),
        &root.join("dev/shm"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size=33554432,mode=1777,uid={uid},gid={gid}").as_str()),
    )
    .unwrap();
    mount(
        Some("tmpfs"),
        &root.join("profile/browserd-files"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size=33554432,mode=0700,uid={uid},gid={gid}").as_str()),
    )
    .unwrap();
    let cwd = std::env::current_dir().unwrap();
    let old_root = root.join(".old-root");
    fs::create_dir(&old_root).unwrap();
    // Chromium creates its own user namespace. A chroot alone leaves the mount
    // namespace root different and makes that CLONE_NEWUSER fail with EPERM.
    nix::unistd::pivot_root(root, &old_root).unwrap();
    std::env::set_current_dir("/").unwrap();
    umount2("/.old-root", MntFlags::MNT_DETACH).unwrap();
    fs::remove_dir("/.old-root").unwrap();
    std::env::set_current_dir(cwd).unwrap();
}

/// Returns false in the parent after the exact child test has completed successfully.
pub fn enter_or_spawn(test_name: &str) -> bool {
    if std::env::var("BROWSERD_BROWSER_FILES_TEST_CHILD")
        .ok()
        .as_deref()
        != Some(test_name)
    {
        assert!(
            std::env::var_os("BROWSERD_TEST_CHROMIUM").is_some(),
            "explicit sandbox-enabled Chromium required"
        );
        let root = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--mount",
                "--pid",
                "--fork",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .env("BROWSERD_BROWSER_FILES_TEST_CHILD", test_name)
            .env("BROWSERD_BROWSER_FILES_MOUNT_ROOT", root.path())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "bounded scratch/Chromium functional subprocess failed"
        );
        return false;
    }
    isolate_filesystem(Path::new(
        &std::env::var_os("BROWSERD_BROWSER_FILES_MOUNT_ROOT").unwrap(),
    ));
    true
}
