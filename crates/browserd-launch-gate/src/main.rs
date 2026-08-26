use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, ExitCode, Stdio};

use browserd_launch_gate::validate_approval;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--")) {
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
    if let Err(error) = validate_approval(&mut std::io::stdin().lock()) {
        eprintln!("browserd launch gate rejected approval: {error}");
        return ExitCode::from(77);
    }
    let Ok(null) = File::open("/dev/null") else {
        return ExitCode::from(70);
    };
    let error = Command::new(target)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::from(null))
        .exec();
    eprintln!("browserd launch gate exec failed: {error}");
    ExitCode::from(70)
}
