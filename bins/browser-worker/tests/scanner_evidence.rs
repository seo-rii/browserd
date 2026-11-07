#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! Protocol fixtures assert fail-closed evidence; they do not qualify a real ClamAV deployment.
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browser_worker::{
    ArtifactScanResult, ArtifactScanner, ClamAvFreshnessPolicy, UnixClamAvScanner,
};
use browserd_session::SessionTime;
use browserd_worker::{ArtifactScanVerdict, DependencyError, WorkerClock, WorkerError};
use chrono::NaiveDateTime;
use sha2::{Digest, Sha256};

const VERSION: &str = "ClamAV 1.4.3/28000/Thu Jan  1 00:00:00 2026";
const FOUND: &[u8] = b"2: stream: Eicar-Test-Signature FOUND\0";
fn uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}
fn built_at() -> u64 {
    u64::try_from(
        NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
            .timestamp_millis(),
    )
    .unwrap()
}
fn policy() -> ClamAvFreshnessPolicy {
    ClamAvFreshnessPolicy::new_utc(Duration::from_secs(48 * 3600), Duration::from_secs(300))
        .unwrap()
}
fn command(stream: &mut UnixStream) -> Vec<u8> {
    let mut value = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("command");
        if byte[0] == 0 {
            return value;
        }
        assert!(value.len() < 4096);
        value.push(byte[0]);
    }
}
fn begin(stream: &mut UnixStream, version: &str) {
    assert_eq!(command(stream), b"zIDSESSION");
    assert_eq!(command(stream), b"zVERSION");
    stream
        .write_all(format!("1: {version}\0").as_bytes())
        .expect("version reply");
}
fn contents(stream: &mut UnixStream) -> Vec<u8> {
    assert_eq!(command(stream), b"zINSTREAM");
    let mut bytes = Vec::new();
    loop {
        let mut size = [0; 4];
        stream.read_exact(&mut size).expect("chunk length");
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 {
            return bytes;
        }
        assert!(size <= 64 * 1024);
        assert!(bytes.len() + size <= 1024 * 1024);
        let start = bytes.len();
        bytes.resize(start + size, 0);
        stream.read_exact(&mut bytes[start..]).expect("chunk");
    }
}
fn finish(stream: &mut UnixStream, version: &str) {
    finish_response(stream, version, b"2: stream: OK\0");
}
fn finish_response(stream: &mut UnixStream, version: &str, response: &[u8]) {
    stream.write_all(response).expect("scan verdict");
    assert_eq!(command(stream), b"zVERSION");
    stream
        .write_all(format!("3: {version}\0").as_bytes())
        .expect("second version");
    assert_eq!(command(stream), b"zEND");
}
fn scan<F>(
    bytes: &[u8],
    clock: Arc<Clock>,
    expected_uid: u32,
    freshness: ClamAvFreshnessPolicy,
    peer: F,
) -> Result<ArtifactScanResult, DependencyError>
where
    F: FnOnce(&mut UnixStream) + Send + 'static,
{
    scan_using(bytes, clock, expected_uid, freshness, peer, true)
}

fn scan_using<F>(
    bytes: &[u8],
    clock: Arc<Clock>,
    expected_uid: u32,
    freshness: ClamAvFreshnessPolicy,
    peer: F,
    observation: bool,
) -> Result<ArtifactScanResult, DependencyError>
where
    F: FnOnce(&mut UnixStream) + Send + 'static,
{
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("clamd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer(&mut stream);
    });
    let scanner = UnixClamAvScanner::new(
        socket,
        expected_uid,
        u64::try_from(bytes.len()).unwrap().max(1),
        Duration::from_secs(2),
        freshness,
        clock,
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = if observation {
        runtime.block_on(scanner.scan_with_observation(bytes))
    } else {
        runtime
            .block_on(scanner.scan(bytes))
            .map(|verdict| ArtifactScanResult {
                verdict,
                observation: None,
            })
    };
    server.join().expect("peer fixture");
    result
}
fn fresh_clock() -> Arc<Clock> {
    Arc::new(Clock(AtomicU64::new(built_at() + 1000)))
}

#[test]
fn authenticated_bracketed_scan_returns_exact_bytes_and_metadata_evidence() {
    let bytes = "검사 대상\0with bytes".as_bytes();
    let expected = bytes.to_vec();
    let result = scan(bytes, fresh_clock(), uid(), policy(), move |peer| {
        begin(peer, VERSION);
        assert_eq!(contents(peer), expected);
        finish(peer, VERSION);
    })
    .unwrap();
    assert_eq!(result.verdict, ArtifactScanVerdict::Clean);
    let evidence = result.observation.expect("required evidence");
    evidence.validate_at(built_at() + 1000).unwrap();
    assert_eq!(evidence.program_version, "1.4.3");
    assert_eq!(evidence.database_version, 28000);
    assert_eq!(evidence.database_built_at_unix_millis, built_at());
    assert_eq!(evidence.expected_peer_uid, uid());
    assert_eq!(evidence.peer_uid, uid());
    assert_eq!(evidence.scanned_size_bytes, bytes.len() as u64);
    assert_eq!(
        evidence.scanned_checksum_sha256,
        <[u8; 32]>::from(Sha256::digest(bytes))
    );
    assert_eq!(
        evidence.version_metadata_sha256,
        <[u8; 32]>::from(Sha256::digest(VERSION))
    );
}

#[test]
fn complete_authenticated_found_retains_exact_observation_and_legacy_verdict_stays_rejected() {
    let bytes: Vec<u8> = (0..64 * 1024 + 1)
        .map(|index| (index % 251) as u8)
        .collect();
    for observation in [true, false] {
        let expected = bytes.clone();
        let result = scan_using(
            &bytes,
            fresh_clock(),
            uid(),
            policy(),
            move |peer| {
                begin(peer, VERSION);
                assert_eq!(contents(peer), expected);
                finish_response(peer, VERSION, FOUND);
            },
            observation,
        )
        .expect("complete authenticated FOUND");
        assert_eq!(result.verdict, ArtifactScanVerdict::Rejected);
        if observation {
            let evidence = result.observation.expect("verified nonclean observation");
            evidence.validate_at(built_at() + 1000).unwrap();
            assert_eq!(evidence.program_version, "1.4.3");
            assert_eq!(evidence.database_version, 28000);
            assert_eq!(evidence.database_built_at_unix_millis, built_at());
            assert_eq!(evidence.expected_peer_uid, uid());
            assert_eq!(evidence.peer_uid, uid());
            assert_eq!(evidence.scanned_size_bytes, bytes.len() as u64);
            assert_eq!(
                evidence.scanned_checksum_sha256,
                <[u8; 32]>::from(Sha256::digest(&bytes))
            );
            assert_eq!(
                evidence.version_metadata_sha256,
                <[u8; 32]>::from(Sha256::digest(VERSION))
            );
        } else {
            assert!(result.observation.is_none());
        }
    }
}

#[test]
fn complete_authenticated_found_is_retained_privately_without_public_success() {
    use std::os::unix::fs::PermissionsExt;

    use browser_worker::{
        ArtifactQuarantineConfig, ArtifactRetentionConfig, ArtifactStoreConfig,
        ProductionArtifactStore, RoutedArtifactStore,
    };
    use browserd_core::{
        ArtifactId, NotificationArtifactState, SessionId, TenantId, WorkerId,
        WorkerNotificationEvent,
    };
    use browserd_session::OwnershipFence;
    use browserd_worker::{ArtifactStoreRequest, SystemWorkerClock};

    let socket_directory = tempfile::tempdir().expect("private scanner socket directory");
    let root = tempfile::tempdir().expect("private artifact root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private artifact permissions");
    let socket = socket_directory.path().join("clamd.sock");
    let listener = UnixListener::bind(&socket).expect("authenticated scanner fixture");
    let bytes = b"unsafe protocol fixture\0exact binary bytes";
    let expected = bytes.to_vec();
    // Use the real store clock and a fresh database timestamp, rather than the fixed
    // protocol-only clock, so this crosses the production freshness check too.
    let version = format!(
        "ClamAV 1.4.3/28000/{}",
        chrono::Utc::now().format("%a %b %e %T %Y")
    );
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().expect("scanner connection");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("scanner read deadline");
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .expect("scanner write deadline");
        begin(&mut peer, &version);
        assert_eq!(contents(&mut peer), expected);
        finish_response(&mut peer, &version, FOUND);
        // Closing after zEND is the authenticated clean EOF required for evidence.
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("artifact runtime");
    let clock = Arc::new(SystemWorkerClock);
    let scanner = UnixClamAvScanner::new(
        socket,
        uid(),
        1024,
        Duration::from_secs(2),
        policy(),
        clock.clone(),
    )
    .expect("real authenticated scanner");
    let store = ProductionArtifactStore::open_with_quarantine(
        ArtifactStoreConfig {
            root: root.path().to_owned(),
            max_file_bytes: 1024,
            max_worker_bytes: 2048,
            max_worker_in_flight_bytes: 1024,
            max_session_bytes: 2048,
            max_session_in_flight_bytes: 1024,
            max_retained_artifacts: 4,
            max_operations: 2,
            chunk_bytes: 7,
            operation_timeout: Duration::from_secs(2),
        },
        runtime.handle().clone(),
        Some(Arc::new(scanner)),
        ArtifactRetentionConfig::default(),
        clock.clone(),
        Some(
            ArtifactQuarantineConfig::new(Duration::from_secs(3600), 1024, 2048, 2048, 4)
                .expect("bounded quarantine policy"),
        ),
    )
    .expect("production quarantine store");
    let request = ArtifactStoreRequest::new(
        TenantId::new(),
        SessionId::new(),
        ArtifactId::new(),
        OwnershipFence::new(WorkerId::new("scanner-quarantine-test").unwrap(), 7, 9, 11),
        bytes.to_vec(),
        "text/plain",
        1024,
    )
    .expect("attributed artifact request");
    // This synchronous call is outside Tokio; the real store uses the multithread handle.
    assert_eq!(store.store(&request), Err(DependencyError::Rejected));
    server.join().expect("complete FOUND protocol fixture");

    let private_key = root
        .path()
        .join(".quarantine")
        .join(request.key().tenant_id().to_string())
        .join(request.key().session_id().to_string())
        .join(request.key().artifact_id().to_string());
    let mut generations = Vec::new();
    for entry in std::fs::read_dir(private_key).expect("committed private artifact") {
        let entry = entry.expect("private artifact entry");
        let file_type = entry.file_type().expect("private entry type");
        if entry.file_name() == "lock" {
            // The stable per-artifact lock is metadata, outside the payload generation.
            assert!(file_type.is_file());
            assert_eq!(
                entry.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            continue;
        }
        assert!(file_type.is_dir(), "unexpected private artifact entry");
        generations.push(entry.path());
    }
    assert_eq!(generations.len(), 1);
    let generation = generations[0].file_name().unwrap().to_str().unwrap();
    assert_eq!(generation.len(), 64);
    assert!(generation.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(std::fs::read(generations[0].join("data")).unwrap(), bytes);
    assert!(
        std::fs::read_dir(root.path().join("objects"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        store
            .get_retained_artifact(request.key(), clock.now().unwrap().get())
            .unwrap()
            .is_none()
    );
    let page = store
        .pending_notifications(None, 32, 8)
        .expect("committed notification page");
    assert!(page.is_complete);
    assert_eq!(page.commits.len(), 1);
    let commit = &page.commits[0];
    commit.validate().expect("valid private authority commit");
    assert_eq!(commit.descriptors().len(), 1);
    assert_eq!(
        commit.descriptors()[0].event(),
        &WorkerNotificationEvent::ArtifactStateChanged {
            artifact_id: request.key().artifact_id().clone(),
            state: NotificationArtifactState::Quarantined,
        }
    );
    assert!(!commit.descriptors().iter().any(|descriptor| matches!(
        descriptor.event(),
        WorkerNotificationEvent::DownloadCompleted { .. }
            | WorkerNotificationEvent::ArtifactStateChanged {
                state: NotificationArtifactState::Available,
                ..
            }
    )));
}

#[test]
fn early_found_without_complete_instream_never_carries_an_observation() {
    let bytes = vec![9; 8 * 1024 * 1024];
    let result = scan(&bytes, fresh_clock(), uid(), policy(), |peer| {
        begin(peer, VERSION);
        assert_eq!(command(peer), b"zINSTREAM");
        peer.write_all(FOUND).expect("early FOUND");
        // Keep the connection alive without draining the full stream, so no EOF/write failure
        // can disguise the early-response branch or mark all bytes sent.
        std::thread::sleep(Duration::from_millis(100));
    })
    .expect("early nonclean verdict");
    assert_eq!(
        result,
        ArtifactScanResult {
            verdict: ArtifactScanVerdict::Rejected,
            observation: None,
        }
    );
}

#[test]
fn freshness_accepts_exact_age_and_future_skew_boundaries_but_rejects_one_ms_beyond() {
    for (now, accept) in [
        (built_at() + 1000, true),
        (built_at() + 1001, false),
        (built_at() - 5000, true),
        (built_at() - 5001, false),
    ] {
        let result = scan(
            b"x",
            Arc::new(Clock(AtomicU64::new(now))),
            uid(),
            ClamAvFreshnessPolicy::new_utc(Duration::from_secs(1), Duration::from_secs(5)).unwrap(),
            move |peer| {
                begin(peer, VERSION);
                if accept {
                    assert_eq!(contents(peer), b"x");
                    finish(peer, VERSION);
                } else {
                    let mut byte = [0];
                    assert_eq!(peer.read(&mut byte).unwrap(), 0, "stale before payload");
                }
            },
        );
        assert_eq!(result.is_ok(), accept, "freshness boundary");
    }
}

#[test]
fn rejects_missing_malformed_database_metadata_before_sending_bytes() {
    for version in [
        "ClamAV 1.4.3",
        "ClamAV 1.4.3/0/Thu Jan  1 00:00:00 2026",
        "ClamAV 1.4.3/028000/Thu Jan  1 00:00:00 2026",
        "ClamAV 1.4.3/28000/Fri Jan  1 00:00:00 2026",
        "ClamAV 1.4.3/28000/Thu Feb 30 00:00:00 2026",
        "ClamAV 1.4.3/28000/Thu Jan  1 00:00:00 2026 UTC",
        "COMMAND UNAVAILABLE",
    ] {
        assert!(
            scan(b"private", fresh_clock(), uid(), policy(), move |peer| {
                begin(peer, version);
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).unwrap(), 0);
            })
            .is_err()
        );
    }
}

#[test]
fn peer_uid_mismatch_closes_before_any_protocol_or_content() {
    assert_eq!(
        scan(
            b"private",
            fresh_clock(),
            uid().wrapping_add(1),
            policy(),
            |peer| {
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).unwrap(), 0);
            }
        ),
        Err(DependencyError::Rejected)
    );
}

#[test]
fn reload_during_scan_and_wrong_second_request_id_are_rejected_without_replay() {
    for verdict in [b"2: stream: OK\0".as_slice(), FOUND] {
        for response in [
            b"3: ClamAV 1.4.3/28001/Thu Jan  1 00:00:00 2026\0".as_slice(),
            b"2: ClamAV 1.4.3/28000/Thu Jan  1 00:00:00 2026\0".as_slice(),
            b"3: ClamAV 1.4.3/28000/Thu Jan  1 00:00:00 2026".as_slice(),
        ] {
            assert!(
                scan(b"x", fresh_clock(), uid(), policy(), move |peer| {
                    begin(peer, VERSION);
                    assert_eq!(contents(peer), b"x");
                    peer.write_all(verdict).unwrap();
                    assert_eq!(command(peer), b"zVERSION");
                    peer.write_all(response).unwrap();
                    if response.ends_with(&[0]) {
                        let mut byte = [0];
                        assert_eq!(
                            peer.read(&mut byte).unwrap(),
                            0,
                            "no replay or END after mismatch"
                        );
                    }
                })
                .is_err()
            );
        }
    }
}

#[test]
fn post_scan_clock_backward_or_database_expiry_never_produces_an_observation() {
    for verdict in [b"2: stream: OK\0".as_slice(), FOUND] {
        for after in [built_at() + 999, built_at() + 2001] {
            let clock = fresh_clock();
            let moved = clock.clone();
            assert!(
                scan(
                    b"x",
                    clock,
                    uid(),
                    ClamAvFreshnessPolicy::new_utc(Duration::from_secs(2), Duration::ZERO).unwrap(),
                    move |peer| {
                        begin(peer, VERSION);
                        assert_eq!(contents(peer), b"x");
                        moved.0.store(after, Ordering::SeqCst);
                        finish_response(peer, VERSION, verdict);
                    },
                )
                .is_err()
            );
        }
    }
}

#[test]
fn missing_bracketing_errors_wrong_ids_truncated_and_oversized_replies_have_no_evidence() {
    for response in [
        b"2: stream: Eicar-Test-Signature FOUND\0".to_vec(),
        b"2: stream: Eicar-Test-Signature FOUND".to_vec(),
        b"2: INSTREAM size limit exceeded\0".to_vec(),
        b"1: stream: OK\0".to_vec(),
        b"2: stream: OK".to_vec(),
        vec![b'x'; 4097],
    ] {
        let result = scan(b"x", fresh_clock(), uid(), policy(), move |peer| {
            begin(peer, VERSION);
            assert_eq!(contents(peer), b"x");
            let _ = peer.write_all(&response);
        });
        assert!(result.is_err());
    }
}

#[test]
fn extra_records_after_end_are_rejected() {
    for verdict in [b"2: stream: OK\0".as_slice(), FOUND] {
        assert!(
            scan(b"x", fresh_clock(), uid(), policy(), move |peer| {
                begin(peer, VERSION);
                assert_eq!(contents(peer), b"x");
                finish_response(peer, VERSION, verdict);
                peer.write_all(b"4: stream: OK\0").unwrap();
            })
            .is_err()
        );
    }
}

#[test]
fn malformed_found_replies_never_start_evidence_bracketing() {
    for response in [
        b"2: stream:  FOUND\0".as_slice(),
        b"2: stream: Eicar\tTest FOUND\0".as_slice(),
        b"2: stream: Eicar-Test  FOUND\0".as_slice(),
    ] {
        assert!(
            scan(b"x", fresh_clock(), uid(), policy(), move |peer| {
                begin(peer, VERSION);
                assert_eq!(contents(peer), b"x");
                peer.write_all(response).unwrap();
                let mut byte = [0];
                assert_eq!(
                    peer.read(&mut byte).unwrap(),
                    0,
                    "no VERSION after malformed verdict"
                );
            })
            .is_err()
        );
    }
}

#[test]
fn large_chunked_input_and_early_error_do_not_deadlock_writer() {
    let bytes = vec![7; 3 * 64 * 1024 + 1];
    let expected = bytes.clone();
    assert!(
        scan(&bytes, fresh_clock(), uid(), policy(), move |peer| {
            begin(peer, VERSION);
            assert_eq!(contents(peer), expected);
            finish(peer, VERSION);
        })
        .is_ok()
    );
    // Larger than the Unix send buffer; the peer does not drain the remaining payload.
    for response in [
        b"2: INSTREAM size limit exceeded\0".as_slice(),
        b"2: stream: OK\0".as_slice(),
    ] {
        let bytes = vec![9; 8 * 1024 * 1024];
        let result = scan(&bytes, fresh_clock(), uid(), policy(), move |peer| {
            begin(peer, VERSION);
            assert_eq!(command(peer), b"zINSTREAM");
            peer.write_all(response).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        assert_eq!(result, Err(DependencyError::Rejected));
    }
}

#[test]
fn size_precheck_and_absolute_deadline_bound_all_protocol_phases() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("clamd.sock");
    let scanner = UnixClamAvScanner::new(
        socket.clone(),
        uid(),
        2,
        Duration::from_millis(50),
        policy(),
        fresh_clock(),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime.block_on(scanner.scan(b"oversize")),
        Err(DependencyError::Rejected)
    );
    assert_eq!(
        runtime.block_on(scanner.scan(b"ok")),
        Err(DependencyError::Unavailable)
    );
    let listener = UnixListener::bind(socket).unwrap();
    let (release, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        for complete_scan in [false, true] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if complete_scan {
                begin(&mut stream, VERSION);
                assert_eq!(contents(&mut stream), b"ok");
                finish_response(&mut stream, VERSION, FOUND);
            }
            // Only the scanner's deadline can finish first. The second connection completes
            // FOUND and both VERSION replies, then withholds the required clean EOF.
            let _ = wait.recv_timeout(Duration::from_secs(2));
        }
    });
    for _ in 0..2 {
        let start = Instant::now();
        assert_eq!(
            runtime.block_on(scanner.scan_with_observation(b"ok")),
            Err(DependencyError::Unavailable)
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }
    server.join().unwrap();
}

#[test]
fn policy_and_constructor_reject_unbounded_or_ambiguous_configuration() {
    assert!(ClamAvFreshnessPolicy::new_utc(Duration::ZERO, Duration::ZERO).is_err());
    assert!(ClamAvFreshnessPolicy::new_utc(Duration::from_nanos(1), Duration::ZERO).is_err());
    assert!(
        ClamAvFreshnessPolicy::new_utc(Duration::from_secs(7 * 86400 + 1), Duration::ZERO).is_err()
    );
    assert!(
        ClamAvFreshnessPolicy::new_utc(Duration::from_secs(1), Duration::from_secs(301)).is_err()
    );
    for (path, size, timeout) in [
        ("relative.sock", 1, Duration::from_secs(1)),
        ("/scanner.sock", 0, Duration::from_secs(1)),
        ("/scanner.sock", 1, Duration::ZERO),
        ("/scanner.sock", 1, Duration::from_secs(301)),
    ] {
        assert!(
            UnixClamAvScanner::new(path.into(), uid(), size, timeout, policy(), fresh_clock())
                .is_err()
        );
    }
}

#[test]
fn legacy_clean_adapter_does_not_invent_an_observation() {
    struct Legacy;
    #[async_trait]
    impl ArtifactScanner for Legacy {
        async fn scan(&self, _: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
            Ok(ArtifactScanVerdict::Clean)
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .block_on(Legacy.scan_with_observation(b"x"))
            .unwrap(),
        ArtifactScanResult {
            verdict: ArtifactScanVerdict::Clean,
            observation: None,
        }
    );
}
