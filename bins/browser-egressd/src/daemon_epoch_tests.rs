use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{DaemonEpochStoreError, allocate_daemon_epoch};

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "browserd-egressd-daemon-epoch-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn canonical_record(epoch: u64) -> String {
    format!("browserd-egressd-daemon-epoch-v1\n{epoch}\n")
}

#[test]
fn first_allocation_persists_epoch_one_canonically() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("first")?;
    let state_path = directory.path().join("daemon.epoch");

    let epoch = allocate_daemon_epoch(&state_path)?;

    assert_eq!(epoch.get(), 1);
    assert_eq!(fs::read_to_string(state_path)?, canonical_record(1));
    Ok(())
}

#[test]
fn sequential_allocations_increment_the_durable_record() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("sequential")?;
    let state_path = directory.path().join("daemon.epoch");

    let first = allocate_daemon_epoch(&state_path)?;
    let second = allocate_daemon_epoch(&state_path)?;
    let third = allocate_daemon_epoch(&state_path)?;

    assert_eq!([first.get(), second.get(), third.get()], [1, 2, 3]);
    assert_eq!(fs::read_to_string(state_path)?, canonical_record(3));
    Ok(())
}

#[test]
fn concurrent_processes_allocate_unique_contiguous_epochs() -> Result<(), Box<dyn Error>> {
    const PROCESS_COUNT: usize = 12;

    let directory = TemporaryDirectory::create("processes")?;
    let state_path = directory.path().join("daemon.epoch");
    let executable = std::env::current_exe()?;
    let test_module = module_path!()
        .split_once("::")
        .map_or(module_path!(), |(_, module)| module);
    let helper_name = format!("{test_module}::process_allocator_helper");
    let mut children = Vec::with_capacity(PROCESS_COUNT);

    for index in 0..PROCESS_COUNT {
        let output_path = directory.path().join(format!("result-{index}"));
        let child = Command::new(&executable)
            .arg("--ignored")
            .arg("--exact")
            .arg(&helper_name)
            .env("BROWSERD_DAEMON_EPOCH_HELPER_STATE", &state_path)
            .env("BROWSERD_DAEMON_EPOCH_HELPER_OUTPUT", output_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        children.push(child);
    }

    for child in &mut children {
        assert!(child.wait()?.success());
    }

    let mut epochs = Vec::with_capacity(PROCESS_COUNT);
    for index in 0..PROCESS_COUNT {
        let value = fs::read_to_string(directory.path().join(format!("result-{index}")))?;
        epochs.push(value.parse::<u64>()?);
    }
    epochs.sort_unstable();

    assert_eq!(epochs, (1..=PROCESS_COUNT as u64).collect::<Vec<_>>());
    assert_eq!(
        fs::read_to_string(state_path)?,
        canonical_record(PROCESS_COUNT as u64)
    );
    Ok(())
}

#[test]
#[ignore = "helper process invoked by concurrent_processes_allocate_unique_contiguous_epochs"]
fn process_allocator_helper() -> Result<(), Box<dyn Error>> {
    let Some(state_path) = std::env::var_os("BROWSERD_DAEMON_EPOCH_HELPER_STATE") else {
        return Ok(());
    };
    let output_path = std::env::var_os("BROWSERD_DAEMON_EPOCH_HELPER_OUTPUT")
        .ok_or("helper output path is missing")?;
    let epoch = allocate_daemon_epoch(Path::new(&state_path))?;
    fs::write(output_path, epoch.get().to_string())?;
    Ok(())
}

#[test]
fn malformed_oversized_and_trailing_records_are_rejected_without_replacement()
-> Result<(), Box<dyn Error>> {
    let records = [
        String::new(),
        "1\n".to_owned(),
        canonical_record(0),
        "browserd-egressd-daemon-epoch-v1\n01\n".to_owned(),
        "browserd-egressd-daemon-epoch-v1\n1\ntrailing".to_owned(),
        "x".repeat(4_096),
    ];

    for (index, record) in records.iter().enumerate() {
        let directory = TemporaryDirectory::create(&format!("malformed-{index}"))?;
        let state_path = directory.path().join("daemon.epoch");
        fs::write(&state_path, record)?;

        let result = allocate_daemon_epoch(&state_path);

        assert!(matches!(result, Err(DaemonEpochStoreError::InvalidRecord)));
        assert_eq!(fs::read(&state_path)?, record.as_bytes());
    }
    Ok(())
}

#[test]
fn maximum_epoch_is_exhausted_without_replacement() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("exhausted")?;
    let state_path = directory.path().join("daemon.epoch");
    let record = canonical_record(u64::MAX);
    fs::write(&state_path, &record)?;

    let result = allocate_daemon_epoch(&state_path);

    assert!(matches!(result, Err(DaemonEpochStoreError::Exhausted)));
    assert_eq!(fs::read_to_string(state_path)?, record);
    Ok(())
}

#[test]
fn state_symlinks_and_non_regular_files_are_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("unsafe-state")?;
    let victim_path = directory.path().join("victim");
    let state_symlink = directory.path().join("state-link");
    let state_directory = directory.path().join("state-directory");
    let victim_record = canonical_record(41);
    fs::write(&victim_path, &victim_record)?;
    symlink(&victim_path, &state_symlink)?;
    fs::create_dir(&state_directory)?;

    assert!(matches!(
        allocate_daemon_epoch(&state_symlink),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
    assert!(matches!(
        allocate_daemon_epoch(&state_directory),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
    assert_eq!(fs::read_to_string(victim_path)?, victim_record);
    Ok(())
}

#[test]
fn lock_symlinks_are_rejected_without_touching_the_state() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("unsafe-lock")?;
    let state_path = directory.path().join("daemon.epoch");
    let lock_path = directory.path().join("daemon.epoch.lock");
    let victim_path = directory.path().join("victim");
    let state_record = canonical_record(7);
    fs::write(&state_path, &state_record)?;
    fs::write(&victim_path, b"victim")?;
    symlink(&victim_path, lock_path)?;

    assert!(matches!(
        allocate_daemon_epoch(&state_path),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
    assert_eq!(fs::read_to_string(state_path)?, state_record);
    assert_eq!(fs::read(victim_path)?, b"victim");
    Ok(())
}

#[test]
fn missing_or_symlinked_parent_is_rejected_without_creation() -> Result<(), Box<dyn Error>> {
    let directory = TemporaryDirectory::create("unsafe-parent")?;
    let missing_parent = directory.path().join("missing");
    let real_parent = directory.path().join("real");
    let parent_link = directory.path().join("parent-link");
    fs::create_dir(&real_parent)?;
    symlink(&real_parent, &parent_link)?;

    assert!(matches!(
        allocate_daemon_epoch(&missing_parent.join("daemon.epoch")),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
    assert!(matches!(
        allocate_daemon_epoch(&parent_link.join("daemon.epoch")),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
    assert!(!missing_parent.exists());
    assert!(!real_parent.join("daemon.epoch").exists());
    Ok(())
}

#[test]
fn path_without_an_explicit_parent_is_rejected() {
    let path = PathBuf::from(OsString::from("daemon.epoch"));

    assert!(matches!(
        allocate_daemon_epoch(&path),
        Err(DaemonEpochStoreError::UnsafePath)
    ));
}
