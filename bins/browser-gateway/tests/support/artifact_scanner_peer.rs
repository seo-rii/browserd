#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Bounded ClamAV protocol peer; this does not qualify a malware engine or database.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

const CALLS: usize = 2;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct ScannerPeer {
    pub socket: PathBuf,
    pub uid: u32,
    pub version_sha256: [u8; 32],
    _directory: tempfile::TempDir,
    thread: Option<JoinHandle<Result<Vec<Vec<u8>>, String>>>,
}

impl ScannerPeer {
    pub(super) fn start(now: u64, calls: Arc<AtomicUsize>) -> Self {
        let directory = tempfile::tempdir().expect("scanner peer directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private scanner peer directory");
        let socket = directory.path().join("clamd.sock");
        let listener = UnixListener::bind(&socket).expect("scanner peer socket");
        listener
            .set_nonblocking(true)
            .expect("nonblocking scanner peer accept");
        let uid = std::fs::symlink_metadata(&socket)
            .expect("scanner peer socket owner")
            .uid();
        let built_at = now
            .checked_sub(3_600_000)
            .expect("scanner fixture timestamp");
        let built_at = DateTime::<Utc>::from_timestamp_millis(
            i64::try_from(built_at).expect("UTC milliseconds"),
        )
        .expect("scanner fixture UTC date");
        let version = format!("ClamAV 1.4.3/1/{}", built_at.format("%a %b %e %H:%M:%S %Y"));
        let version_sha256 = Sha256::digest(version.as_bytes()).into();
        let thread = thread::spawn(move || serve(listener, &version, &calls));
        Self {
            socket,
            uid,
            version_sha256,
            _directory: directory,
            thread: Some(thread),
        }
    }

    pub(super) fn finish(&mut self) -> Vec<Vec<u8>> {
        let result = self
            .thread
            .take()
            .expect("scanner peer may finish only once")
            .join()
            .expect("scanner peer thread should join");
        result.expect("two exact scanner protocol sessions should finish")
    }
}

impl Drop for ScannerPeer {
    fn drop(&mut self) {
        // Every accept/read/write shares the same absolute deadline. Joining here cannot leave
        // a socket thread behind or panic again when the surrounding test already panics.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.min(IO_TIMEOUT))
        .ok_or_else(|| "scanner peer absolute deadline elapsed".to_owned())
}

fn read_exact(stream: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    let mut read = 0;
    while read < bytes.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| "set scanner read timeout".to_owned())?;
        let count = stream
            .read(&mut bytes[read..])
            .map_err(|_| "read scanner protocol frame".to_owned())?;
        if count == 0 {
            return Err("scanner peer received truncated protocol frame".to_owned());
        }
        read += count;
    }
    Ok(())
}

fn write_all(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    let mut written = 0;
    while written < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| "set scanner write timeout".to_owned())?;
        let count = stream
            .write(&bytes[written..])
            .map_err(|_| "write scanner protocol response".to_owned())?;
        if count == 0 {
            return Err("scanner peer response made no progress".to_owned());
        }
        written += count;
    }
    Ok(())
}

fn expect_command(
    stream: &mut UnixStream,
    expected: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut command = vec![0; expected.len() + 1];
    read_exact(stream, &mut command, deadline)?;
    if command.last() != Some(&0) || &command[..expected.len()] != expected {
        return Err("scanner peer received unexpected command or command framing".to_owned());
    }
    Ok(())
}

fn session(stream: &mut UnixStream, version: &str, deadline: Instant) -> Result<Vec<u8>, String> {
    expect_command(stream, b"zIDSESSION", deadline)?;
    expect_command(stream, b"zVERSION", deadline)?;
    write_all(stream, format!("1: {version}\0").as_bytes(), deadline)?;
    expect_command(stream, b"zINSTREAM", deadline)?;
    let mut scanned = Vec::with_capacity(1024);
    loop {
        let mut encoded = [0; 4];
        read_exact(stream, &mut encoded, deadline)?;
        let length = usize::try_from(u32::from_be_bytes(encoded))
            .map_err(|_| "scanner frame length overflow".to_owned())?;
        if length == 0 {
            break;
        }
        if length > 64 * 1024 || length > 1024 - scanned.len() {
            return Err("scanner INSTREAM exceeded frame or total byte bound".to_owned());
        }
        let start = scanned.len();
        scanned.resize(start + length, 0);
        read_exact(stream, &mut scanned[start..], deadline)?;
    }
    write_all(stream, b"2: stream: OK\0", deadline)?;
    expect_command(stream, b"zVERSION", deadline)?;
    write_all(stream, format!("3: {version}\0").as_bytes(), deadline)?;
    expect_command(stream, b"zEND", deadline)?;
    Ok(scanned)
}

fn serve(
    listener: UnixListener,
    version: &str,
    calls: &AtomicUsize,
) -> Result<Vec<Vec<u8>>, String> {
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    let mut payloads = Vec::with_capacity(CALLS);
    for _ in 0..CALLS {
        let mut stream = loop {
            remaining(deadline)?;
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return Err("accept scanner peer connection".to_owned()),
            }
        };
        calls.fetch_add(1, Ordering::SeqCst);
        payloads.push(session(&mut stream, version, deadline)?);
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(payloads),
        Ok(_) => Err("scanner peer received more than two connections".to_owned()),
        Err(_) => Err("inspect scanner peer connection bound".to_owned()),
    }
}
