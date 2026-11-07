use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, ExitCode, Stdio};

use browserd_launch_gate::{SANDBOX_SCRATCH_PATH, send_scratch_offer, validate_approval};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    let export_scratch = first.as_deref() == Some(std::ffi::OsStr::new("--export-scratch"));
    let separator = if export_scratch {
        arguments.next()
    } else {
        first
    };
    if separator.as_deref() != Some(std::ffi::OsStr::new("--")) {
        return ExitCode::from(64);
    }
    let Some(target) = arguments.next() else {
        return ExitCode::from(64);
    };
    let target_path = Path::new(&target);
    if !target_path.is_absolute()
        || target_path == Path::new("/")
        || target_path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return ExitCode::from(64);
    }
    if export_scratch {
        let offered = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(SANDBOX_SCRATCH_PATH)
            .and_then(|directory| {
                // SAFETY: stdin remains owned by this process until the target exec replaces it.
                let control = unsafe { BorrowedFd::borrow_raw(nix::libc::STDIN_FILENO) };
                send_scratch_offer(control, directory.as_fd())
            });
        if let Err(error) = offered {
            eprintln!("browserd launch gate rejected scratch handoff: {error}");
            return ExitCode::from(77);
        }
    }
    if let Err(error) = validate_approval(&mut std::io::stdin().lock()) {
        eprintln!("browserd launch gate rejected approval: {error}");
        return ExitCode::from(77);
    }
    let Ok(null) = File::open("/dev/null") else {
        return ExitCode::from(70);
    };
    // Preserve the catalog-bound native defaults installed by bubblewrap.
    let native_environment: Vec<_> = ["LANG", "LC_ALL", "LANGUAGE", "TZ"]
        .into_iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
        .collect();
    let error = Command::new(target)
        .args(arguments)
        .env_clear()
        .envs(native_environment)
        .stdin(Stdio::from(null))
        .exec();
    eprintln!("browserd launch gate exec failed: {error}");
    ExitCode::from(70)
}
