use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use browserd_egress::DaemonEpoch;

const RECORD_HEADER: &str = "browserd-egressd-daemon-epoch-v1\n";
const MAX_RECORD_BYTES: usize = 64;
const MAX_TEMPORARY_FILE_ATTEMPTS: u64 = 256;

// Linux flags from asm-generic/fcntl.h. browser-egressd is a Linux daemon.
const O_DIRECTORY: i32 = 0o200_000;
const O_NONBLOCK: i32 = 0o4_000;
const O_NOFOLLOW: i32 = 0o400_000;

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum DaemonEpochStoreError {
    UnsafePath,
    InvalidRecord,
    Exhausted,
    Io(io::Error),
}

impl fmt::Display for DaemonEpochStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath => formatter.write_str("daemon epoch path is unsafe"),
            Self::InvalidRecord => formatter.write_str("daemon epoch record is invalid"),
            Self::Exhausted => formatter.write_str("daemon epoch space is exhausted"),
            Self::Io(error) => write!(formatter, "daemon epoch storage failed: {error}"),
        }
    }
}

impl Error for DaemonEpochStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnsafePath | Self::InvalidRecord | Self::Exhausted => None,
        }
    }
}

impl From<io::Error> for DaemonEpochStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn allocate_daemon_epoch(state_path: &Path) -> Result<DaemonEpoch, DaemonEpochStoreError> {
    let parent_path = explicit_parent(state_path)?;
    validate_path_components(state_path)?;
    validate_parent_chain(parent_path)?;
    let parent_directory = open_parent_directory(parent_path)?;

    let lock_path = sibling_path(state_path, ".lock")?;
    let (lock_file, created_lock) = open_lock_file(&lock_path)?;
    lock_file.lock()?;

    validate_parent_chain(parent_path)?;
    if created_lock {
        lock_file.sync_all()?;
        parent_directory.sync_all()?;
    }

    let current_epoch = read_current_epoch(state_path)?;
    let next_epoch = match current_epoch {
        Some(current_epoch) => current_epoch
            .checked_add(1)
            .ok_or(DaemonEpochStoreError::Exhausted)?,
        None => 1,
    };
    let daemon_epoch = DaemonEpoch::new(next_epoch).ok_or(DaemonEpochStoreError::InvalidRecord)?;

    replace_record(state_path, parent_path, &parent_directory, next_epoch)?;
    Ok(daemon_epoch)
}

fn explicit_parent(state_path: &Path) -> Result<&Path, DaemonEpochStoreError> {
    if state_path.file_name().is_none() {
        return Err(DaemonEpochStoreError::UnsafePath);
    }
    state_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(DaemonEpochStoreError::UnsafePath)
}

fn validate_path_components(path: &Path) -> Result<(), DaemonEpochStoreError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(DaemonEpochStoreError::UnsafePath);
    }
    Ok(())
}

fn validate_parent_chain(parent_path: &Path) -> Result<(), DaemonEpochStoreError> {
    for ancestor in parent_path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(ancestor).map_err(map_path_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DaemonEpochStoreError::UnsafePath);
        }
    }
    Ok(())
}

fn open_parent_directory(parent_path: &Path) -> Result<File, DaemonEpochStoreError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(parent_path)
        .map_err(map_path_error)?;
    if !directory.metadata()?.is_dir() {
        return Err(DaemonEpochStoreError::UnsafePath);
    }
    Ok(directory)
}

fn sibling_path(state_path: &Path, suffix: &str) -> Result<PathBuf, DaemonEpochStoreError> {
    let parent_path = explicit_parent(state_path)?;
    let mut file_name = state_path
        .file_name()
        .map(OsString::from)
        .ok_or(DaemonEpochStoreError::UnsafePath)?;
    file_name.push(suffix);
    Ok(parent_path.join(file_name))
}

fn open_lock_file(lock_path: &Path) -> Result<(File, bool), DaemonEpochStoreError> {
    loop {
        match fs::symlink_metadata(lock_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(DaemonEpochStoreError::UnsafePath);
                }
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(O_NOFOLLOW | O_NONBLOCK)
                    .open(lock_path)
                    .map_err(map_path_error)?;
                if !file.metadata()?.is_file() {
                    return Err(DaemonEpochStoreError::UnsafePath);
                }
                return Ok((file, false));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(O_NOFOLLOW | O_NONBLOCK)
                    .open(lock_path)
                {
                    Ok(file) => return Ok((file, true)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(map_path_error(error)),
                }
            }
            Err(error) => return Err(map_path_error(error)),
        }
    }
}

fn read_current_epoch(state_path: &Path) -> Result<Option<u64>, DaemonEpochStoreError> {
    match fs::symlink_metadata(state_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(DaemonEpochStoreError::UnsafePath);
            }
            if metadata.len() > MAX_RECORD_BYTES as u64 {
                return Err(DaemonEpochStoreError::InvalidRecord);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_path_error(error)),
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(state_path)
        .map_err(map_path_error)?;
    if !file.metadata()?.is_file() {
        return Err(DaemonEpochStoreError::UnsafePath);
    }

    let mut record = Vec::with_capacity(MAX_RECORD_BYTES);
    Read::by_ref(&mut file)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut record)?;
    if record.len() > MAX_RECORD_BYTES {
        return Err(DaemonEpochStoreError::InvalidRecord);
    }
    parse_record(&record).map(Some)
}

fn parse_record(record: &[u8]) -> Result<u64, DaemonEpochStoreError> {
    let record = std::str::from_utf8(record).map_err(|_| DaemonEpochStoreError::InvalidRecord)?;
    let digits = record
        .strip_prefix(RECORD_HEADER)
        .and_then(|remainder| remainder.strip_suffix('\n'))
        .ok_or(DaemonEpochStoreError::InvalidRecord)?;
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(DaemonEpochStoreError::InvalidRecord);
    }
    let epoch = digits
        .parse::<u64>()
        .map_err(|_| DaemonEpochStoreError::InvalidRecord)?;
    if epoch == 0 || canonical_record(epoch) != record {
        return Err(DaemonEpochStoreError::InvalidRecord);
    }
    Ok(epoch)
}

fn replace_record(
    state_path: &Path,
    parent_path: &Path,
    parent_directory: &File,
    epoch: u64,
) -> Result<(), DaemonEpochStoreError> {
    let (temporary_path, mut temporary_file) = create_temporary_file(state_path)?;
    let mut cleanup = TemporaryFileCleanup::new(temporary_path.clone());
    temporary_file.write_all(canonical_record(epoch).as_bytes())?;
    temporary_file.sync_all()?;
    drop(temporary_file);

    validate_parent_chain(parent_path)?;
    validate_replace_target(state_path)?;
    fs::rename(&temporary_path, state_path).map_err(map_path_error)?;
    cleanup.disarm();
    parent_directory.sync_all()?;
    Ok(())
}

fn create_temporary_file(state_path: &Path) -> Result<(PathBuf, File), DaemonEpochStoreError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let suffix = format!(".tmp.{}.{sequence}", std::process::id());
        let temporary_path = sibling_path(state_path, &suffix)?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_path_error(error)),
        }
    }
    Err(DaemonEpochStoreError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique daemon epoch temporary file",
    )))
}

fn validate_replace_target(state_path: &Path) -> Result<(), DaemonEpochStoreError> {
    match fs::symlink_metadata(state_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(DaemonEpochStoreError::UnsafePath)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_path_error(error)),
    }
}

fn canonical_record(epoch: u64) -> String {
    format!("{RECORD_HEADER}{epoch}\n")
}

fn map_path_error(error: io::Error) -> DaemonEpochStoreError {
    // Linux returns ELOOP (40) when O_NOFOLLOW encounters a symbolic link.
    if error.raw_os_error() == Some(40)
        || matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory
        )
    {
        DaemonEpochStoreError::UnsafePath
    } else {
        DaemonEpochStoreError::Io(error)
    }
}

struct TemporaryFileCleanup {
    path: Option<PathBuf>,
}

impl TemporaryFileCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryFileCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
#[path = "daemon_epoch_tests.rs"]
mod tests;
