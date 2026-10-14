#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/quarantine.rs"]
mod quarantine;

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::Ordering;
use std::time::Duration;

use browser_worker::{ArtifactQuarantineConfig, RoutedArtifactStore};
use browserd_artifacts::{
    ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactReadLimits,
};
use browserd_core::{NotificationArtifactState, SessionId, TenantId};
use browserd_worker::{
    ArtifactPublication, ArtifactReadRequest, ArtifactScanVerdict, DependencyError,
};
use sha2::{Digest, Sha256};

use quarantine::*;

#[test]
fn quarantine_policy_is_explicit_finite_and_intersects_existing_store_limits() {
    for (retention, file, worker, session, count) in [
        (Duration::ZERO, 4, 8, 8, 2),
        (Duration::from_millis(DAY + 1), 4, 8, 8, 2),
        (Duration::from_millis(100), 0, 8, 8, 2),
        (Duration::from_millis(100), 4, 0, 8, 2),
        (Duration::from_millis(100), 4, 8, 0, 2),
        (Duration::from_millis(100), 4, 8, 8, 0),
    ] {
        assert!(ArtifactQuarantineConfig::new(retention, file, worker, session, count).is_err());
    }
    assert!(ArtifactQuarantineConfig::new(Duration::from_millis(DAY), 4, 8, 8, 2).is_ok());
    let h = Harness::new();
    assert!(h.open(h.config(), None, Some(policy(4, 8, 8, 2))).is_err());
    for policy in [
        policy(9, 16, 12, 2),
        policy(4, 17, 8, 2),
        policy(4, 8, 13, 2),
        policy(4, 8, 8, 9),
    ] {
        assert!(
            h.open(h.config(), Some(Scan::Rejected), Some(policy))
                .is_err()
        );
    }
    assert!(h.all_payloads().is_empty());
}

#[test]
fn default_nonclean_rejection_never_retains_upload_or_download_bytes() {
    for source in [
        ArtifactContentSource::ClientUpload,
        ArtifactContentSource::BrowserDownload,
    ] {
        for scan in [Scan::Rejected, Scan::Quarantined] {
            let h = Harness::new();
            let store = h
                .open(h.config(), Some(scan), None)
                .expect("default metadata-only policy");
            let input = request(TenantId::new(), SessionId::new(), b"unsafe", source);
            assert_eq!(store.store(&input), Err(DependencyError::Rejected));
            assert!(h.all_payloads().is_empty());
            assert!(
                std::fs::read_dir(h.root.path().join(".multipart"))
                    .expect("multipart stages")
                    .next()
                    .is_none()
            );
            assert!(
                std::fs::read_dir(h.root.path().join("objects"))
                    .expect("public objects")
                    .next()
                    .is_none()
            );
            let state = if matches!(scan, Scan::Quarantined) {
                NotificationArtifactState::Quarantined
            } else {
                NotificationArtifactState::Rejected
            };
            let pending = commits(&store);
            assert_eq!(pending.len(), 1);
            assert_state(&pending[0], &input, state);
            no_public_success(&store);
        }
    }
}

#[test]
fn invalid_or_absent_nonclean_scan_observation_never_authorizes_private_bytes() {
    for scan in [
        Scan::MissingObservation,
        Scan::WrongSize,
        Scan::WrongChecksum,
        Scan::WrongUid,
        Scan::Stale,
        Scan::Future,
        Scan::Failed,
    ] {
        let h = Harness::new();
        let store = h
            .open(h.config(), Some(scan), Some(policy(8, 16, 12, 8)))
            .expect("opt-in store");
        let input = request(
            TenantId::new(),
            SessionId::new(),
            b"unsafe",
            ArtifactContentSource::ClientUpload,
        );
        assert_eq!(
            store.store(&input),
            Err(DependencyError::Rejected),
            "{scan:?}"
        );
        assert!(
            h.all_payloads().is_empty(),
            "{scan:?} must be metadata-only"
        );
        for directory in ["objects", ".multipart"] {
            assert!(
                std::fs::read_dir(h.root.path().join(directory))
                    .expect("payload inventory")
                    .next()
                    .is_none(),
                "{scan:?} cannot leave bytes in {directory}"
            );
        }
        let pending = commits(&store);
        assert_eq!(pending.len(), 1);
        assert_state(&pending[0], &input, NotificationArtifactState::Rejected);
        no_public_success(&store);
        // Failed evidence releases its admission charge rather than consuming private byte quota.
        assert!(
            store
                .store(&request(
                    TenantId::new(),
                    SessionId::new(),
                    b"capacity",
                    ArtifactContentSource::Generated
                ))
                .is_ok()
        );
        assert_eq!(h.scanner_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn retained_nonclean_bytes_are_private_and_never_publicly_readable_or_publishable() {
    for source in [
        ArtifactContentSource::ClientUpload,
        ArtifactContentSource::BrowserDownload,
    ] {
        for scan in [Scan::Rejected, Scan::Quarantined] {
            let h = Harness::new();
            let store = h
                .open(h.config(), Some(scan), Some(policy(8, 16, 12, 8)))
                .expect("opt-in store");
            let input = request(TenantId::new(), SessionId::new(), b"unsafe", source);
            assert_eq!(store.store(&input), Err(DependencyError::Rejected));
            let payloads = h.payloads(input.key());
            assert_eq!(payloads.len(), 1);
            let payload = &payloads[0];
            assert_eq!(
                std::fs::read(payload).expect("private bytes"),
                input.bytes()
            );
            let metadata = std::fs::symlink_metadata(payload).expect("private regular file");
            assert!(metadata.is_file());
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            let mut ancestor = payload.parent().expect("generation directory");
            while ancestor != h.root.path() {
                let metadata = std::fs::symlink_metadata(ancestor).expect("private directory");
                assert!(metadata.is_dir());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
                ancestor = ancestor.parent().expect("private root ancestor");
            }
            let generation = generation(payload);
            let checksum = ArtifactChecksum::new(Sha256::digest(input.bytes()).into());
            let metadata = ArtifactContentMetadata::new(
                input.bytes().len() as u64,
                checksum,
                "text/plain",
                source,
                input.origin(),
            )
            .expect("metadata");
            assert!(
                store
                    .open_read(
                        &ArtifactReadRequest::new(
                            input.key().clone(),
                            input.fence().clone(),
                            metadata.clone(),
                            generation,
                            3
                        )
                        .expect("read request")
                    )
                    .is_err()
            );
            assert!(
                store
                    .get_retained_artifact(input.key(), START)
                    .expect("public metadata")
                    .is_none()
            );
            assert!(
                store
                    .list_retained_artifacts(
                        input.key().tenant_id(),
                        input.key().session_id(),
                        None,
                        8,
                        START
                    )
                    .expect("public list")
                    .is_empty()
            );
            assert!(
                ArtifactPublication::new(
                    input.key().clone(),
                    input.fence().clone(),
                    metadata,
                    generation,
                    Some(ArtifactScanVerdict::Rejected),
                    None,
                    START,
                    START + 100
                )
                .is_err()
            );
            // Even an otherwise-valid generated publication cannot adopt a private quarantine generation.
            let forged = ArtifactPublication::new(
                input.key().clone(),
                input.fence().clone(),
                ArtifactContentMetadata::new(
                    input.bytes().len() as u64,
                    checksum,
                    "text/plain",
                    ArtifactContentSource::Generated,
                    "quarantine-capacity-probe",
                )
                .expect("generated metadata"),
                generation,
                None,
                None,
                START,
                START + 100,
            )
            .expect("syntactically valid public claim");
            assert!(store.publish_artifact(&forged).is_err());
            assert!(
                store
                    .open_retained_artifact(
                        &forged,
                        ArtifactReadLimits::new(3).expect("limits"),
                        START
                    )
                    .is_err()
            );
            let pending = commits(&store);
            assert_eq!(pending.len(), 1);
            assert_state(&pending[0], &input, NotificationArtifactState::Quarantined);
            assert_eq!(pending[0].occurred_at_unix_ms(), START);
            assert_eq!(store.store(&input), Err(DependencyError::Rejected));
            assert_eq!(
                commits(&store),
                pending,
                "exact rejection retry cannot create a new public transition"
            );
            assert_eq!(
                h.payloads(input.key()),
                payloads,
                "exact retry preserves the sealed generation"
            );
            no_public_success(&store);
        }
    }
}

#[test]
fn private_file_worker_session_and_count_quotas_admit_no_excess_payload() {
    // Each private bound is lower than the general artifact bound, so failures isolate that policy.
    for bound in ["file", "worker", "session", "count"] {
        let h = Harness::new();
        let limits = match bound {
            "file" => policy(4, 16, 12, 8),
            "worker" => policy(6, 6, 6, 8),
            "session" => policy(4, 8, 4, 8),
            "count" => policy(8, 16, 12, 1),
            _ => unreachable!(),
        };
        let store = h
            .open(h.config(), Some(Scan::Rejected), Some(limits))
            .expect("bounded quarantine");
        let tenant = TenantId::new();
        let session = SessionId::new();
        if bound == "file" {
            let input = request(
                tenant,
                session,
                b"bad!!",
                ArtifactContentSource::ClientUpload,
            );
            assert_eq!(store.store(&input), Err(DependencyError::Rejected));
            assert!(h.all_payloads().is_empty());
            assert_state(
                &commits(&store)[0],
                &input,
                NotificationArtifactState::Rejected,
            );
            continue;
        }
        let bytes: &[u8] = if bound == "worker" { b"bad!" } else { b"bad" };
        let first = request(
            tenant.clone(),
            session.clone(),
            bytes,
            ArtifactContentSource::ClientUpload,
        );
        assert_eq!(store.store(&first), Err(DependencyError::Rejected));
        assert_eq!(h.payloads(first.key()).len(), 1);
        let next_session = if bound == "session" {
            session
        } else {
            SessionId::new()
        };
        let second = request(
            tenant.clone(),
            next_session,
            bytes,
            ArtifactContentSource::ClientUpload,
        );
        assert_eq!(store.store(&second), Err(DependencyError::Rejected));
        assert!(
            h.payloads(second.key()).is_empty(),
            "{bound} cap must reject before sealing excess bytes"
        );
        assert_eq!(h.all_payloads().len(), 1);
        if bound == "session" {
            let third = request(
                tenant,
                SessionId::new(),
                bytes,
                ArtifactContentSource::ClientUpload,
            );
            assert_eq!(store.store(&third), Err(DependencyError::Rejected));
            assert_eq!(
                h.payloads(third.key()).len(),
                1,
                "a different session has independent private capacity"
            );
            assert_eq!(h.all_payloads().len(), 2);
        }
        no_public_success(&store);
    }
}

#[test]
fn expiry_waits_for_exact_notification_ack_and_disabled_reopen_finishes_positive_deletion() {
    let h = Harness::new();
    let mut config = h.config();
    config.max_worker_bytes = 8;
    config.max_session_bytes = 8;
    let store = h
        .open(
            config.clone(),
            Some(Scan::Rejected),
            Some(policy(8, 8, 8, 1)),
        )
        .expect("opt-in store");
    let input = request(
        TenantId::new(),
        SessionId::new(),
        b"bad!",
        ArtifactContentSource::ClientUpload,
    );
    assert_eq!(store.store(&input), Err(DependencyError::Rejected));
    let payload = h.payloads(input.key()).pop().expect("sealed payload");
    let generation = generation(&payload);
    let original = commits(&store).pop().expect("durable Quarantined batch");
    assert_state(&original, &input, NotificationArtifactState::Quarantined);
    h.clock.set(START + 101);
    settle(&store, 1);
    assert!(
        payload.exists(),
        "pending exact source delivery pins expired bytes"
    );
    let capacity = request(
        TenantId::new(),
        SessionId::new(),
        b"five!",
        ArtifactContentSource::Generated,
    );
    assert!(
        store.store(&capacity).is_err(),
        "expired-but-pinned bytes retain their full worker charge"
    );
    drop(store);
    let store = h
        .open(config.clone(), None, None)
        .expect("disabled reopen owns previous quarantine authority");
    assert_eq!(commits(&store), vec![original.clone()]);
    assert!(payload.exists());
    assert!(store.store(&capacity).is_err());
    // No fabricated ACK can authorize cleanup of the original pending batch.
    let mut foreign = serde_json::to_value(original.ack()).expect("public ACK wire");
    foreign["digest"] = serde_json::to_value([99_u8; 32]).expect("foreign digest");
    let foreign: browserd_core::NotificationAck =
        serde_json::from_value(foreign).expect("well-formed foreign digest");
    assert!(store.acknowledge_notifications(&foreign).is_err());
    settle(&store, 1);
    assert!(payload.exists());
    store
        .acknowledge_notifications(&original.ack())
        .expect("exact source head ACK");
    drop(store);
    let store = h
        .open(config, None, None)
        .expect("lost ACK reply and cleanup restart");
    store
        .acknowledge_notifications(&original.ack())
        .expect("exact lost ACK reply retry");
    settle(&store, 1);
    assert!(
        !payload.exists(),
        "positive exact deletion removes bytes before charge reuse"
    );
    let tombstone = quarantine_key(h.root.path(), input.key())
        .join(format!(".deleted-{}", hex::encode(generation.as_bytes())));
    assert!(
        tombstone.join("receipt").is_file(),
        "exact private deletion proof remains durable"
    );
    assert!(!tombstone.join("data").exists());
    assert!(
        commits(&store).is_empty(),
        "private retirement adds no public success or deletion event"
    );
    assert!(
        store.store(&capacity).is_ok(),
        "only positive private deletion releases the charge"
    );
    assert!(
        store
            .get_retained_artifact(input.key(), h.clock.millis())
            .expect("still private")
            .is_none()
    );
}

#[test]
fn bounded_maintenance_visits_each_expired_private_generation_without_starvation() {
    let h = Harness::new();
    let store = h
        .open(h.config(), Some(Scan::Rejected), Some(policy(4, 12, 4, 6)))
        .expect("bounded store");
    let tenant = TenantId::new();
    let mut paths = vec![];
    for _ in 0..6 {
        let input = request(
            tenant.clone(),
            SessionId::new(),
            b"no",
            ArtifactContentSource::ClientUpload,
        );
        assert_eq!(store.store(&input), Err(DependencyError::Rejected));
        paths.extend(h.payloads(input.key()));
    }
    assert_eq!(paths.len(), 6);
    acknowledge_all(&store);
    h.clock.set(START + 101);
    settle(&store, 1);
    assert!(paths.iter().all(|path| !path.exists()));
    assert!(h.all_payloads().is_empty());
    assert!(commits(&store).is_empty());
    assert!(
        store
            .store(&request(
                tenant,
                SessionId::new(),
                b"capacity",
                ArtifactContentSource::Generated
            ))
            .is_ok()
    );
}

#[test]
fn changed_private_payload_is_not_deleted_or_credited_as_the_original_generation() {
    use std::io::Write;
    let h = Harness::new();
    let mut config = h.config();
    config.max_worker_bytes = 8;
    config.max_session_bytes = 8;
    let store = h
        .open(config, Some(Scan::Rejected), Some(policy(8, 8, 8, 1)))
        .expect("opt-in store");
    let input = request(
        TenantId::new(),
        SessionId::new(),
        b"bad!",
        ArtifactContentSource::ClientUpload,
    );
    assert_eq!(store.store(&input), Err(DependencyError::Rejected));
    let payload = h.payloads(input.key()).pop().expect("private generation");
    acknowledge_all(&store);
    let replacement = payload.with_file_name("replacement");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&replacement)
        .expect("private replacement");
    file.write_all(b"evil")
        .expect("different same-sized payload");
    file.sync_all().expect("replacement durable");
    std::fs::rename(replacement, &payload).expect("replace bytes without adopting a new authority");
    h.clock.set(START + 101);
    settle(&store, 1);
    assert_eq!(
        std::fs::read(&payload).expect("replacement survives"),
        b"evil"
    );
    assert!(
        store
            .store(&request(
                TenantId::new(),
                SessionId::new(),
                b"five!",
                ArtifactContentSource::Generated
            ))
            .is_err(),
        "unconfirmed exact deletion must keep the original charge"
    );
    assert!(commits(&store).is_empty());
}

#[test]
fn reduced_general_limits_recover_prior_private_authorities_and_keep_them_charged_until_delete() {
    let h = Harness::new();
    let store = h
        .open(h.config(), Some(Scan::Rejected), Some(policy(8, 16, 12, 8)))
        .expect("original private retention policy");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let mut paths = vec![];
    for bytes in [b"bad!", b"old!"] {
        let input = request(
            tenant.clone(),
            session.clone(),
            bytes,
            ArtifactContentSource::ClientUpload,
        );
        assert_eq!(store.store(&input), Err(DependencyError::Rejected));
        paths.extend(h.payloads(input.key()));
    }
    assert_eq!(paths.len(), 2);
    let original = commits(&store);
    assert!(!original.is_empty());
    drop(store);

    let mut reduced = h.config();
    reduced.max_file_bytes = 2;
    reduced.max_worker_bytes = 3;
    reduced.max_worker_in_flight_bytes = 2;
    reduced.max_session_bytes = 3;
    reduced.max_session_in_flight_bytes = 2;
    reduced.max_retained_artifacts = 1;
    reduced.chunk_bytes = 2;
    h.clock.set(START + 101);
    let store = h
        .open(reduced, None, None)
        .expect("smaller general admission limits cannot discard existing durable inventory");
    assert_eq!(commits(&store), original);
    assert_eq!(h.all_payloads().len(), 2);
    for path in &paths {
        assert_eq!(
            std::fs::metadata(path).expect("prior private bytes").len(),
            4
        );
    }
    let capacity = request(tenant, session, b"ok", ArtifactContentSource::Generated);
    assert!(
        store.store(&capacity).is_err(),
        "both old byte and count charges survive lower general admission limits"
    );
    settle(&store, 1);
    assert!(paths.iter().all(|path| path.exists()));
    acknowledge_all(&store);
    settle(&store, 1);
    assert!(paths.iter().all(|path| !path.exists()));
    assert!(h.all_payloads().is_empty());
    assert!(commits(&store).is_empty());
    assert!(
        store.store(&capacity).is_ok(),
        "positive exact cleanup restores admission within the new general limits"
    );
}

#[test]
fn old_scan_observation_reopens_against_original_admission_and_ack_drains_after_two_days() {
    let h = Harness::new();
    let mut config = h.config();
    config.max_worker_bytes = 8;
    config.max_session_bytes = 8;
    let store = h
        .open(
            config.clone(),
            Some(Scan::Rejected),
            Some(policy(8, 8, 8, 1)),
        )
        .expect("fresh original scan observation");
    let input = request(
        TenantId::new(),
        SessionId::new(),
        b"unsafe",
        ArtifactContentSource::BrowserDownload,
    );
    assert_eq!(store.store(&input), Err(DependencyError::Rejected));
    let payload = h.payloads(input.key()).pop().expect("private bytes");
    let original = commits(&store).pop().expect("original source notification");
    assert_state(&original, &input, NotificationArtifactState::Quarantined);
    assert_eq!(original.occurred_at_unix_ms(), START);
    drop(store);

    // Far beyond both the fixture's 500ms scan freshness horizon and the 24h terminal retry window.
    h.clock.set(START + 2 * DAY + 1);
    let store = h
        .open(config.clone(), None, None)
        .expect("recovery validates evidence at original admission, not the restart clock");
    assert_eq!(commits(&store), vec![original.clone()]);
    assert_eq!(
        std::fs::read(&payload).expect("pending private bytes"),
        input.bytes()
    );
    settle(&store, 1);
    assert!(
        payload.exists(),
        "old pending delivery still owns the private generation"
    );
    let capacity = request(
        TenantId::new(),
        SessionId::new(),
        b"new",
        ArtifactContentSource::Generated,
    );
    assert!(
        store.store(&capacity).is_err(),
        "old pending bytes remain charged"
    );
    store
        .acknowledge_notifications(&original.ack())
        .expect("original exact source ACK");
    drop(store);
    let store = h
        .open(config, None, None)
        .expect("cleanup recovery remains valid with the old original observation");
    store
        .acknowledge_notifications(&original.ack())
        .expect("recover lost ACK reply without rescanning");
    settle(&store, 1);
    assert!(!payload.exists());
    assert!(h.all_payloads().is_empty());
    assert!(commits(&store).is_empty());
    assert!(store.store(&capacity).is_ok());
    assert_eq!(
        h.scanner_calls.load(Ordering::SeqCst),
        1,
        "durable recovery never rescans old bytes"
    );
}

#[test]
fn retiring_newer_quarantine_preserves_older_pending_authority_across_compacted_restart() {
    let h = Harness::new();
    let mut config = h.config();
    config.max_worker_bytes = 8;
    config.max_session_bytes = 8;
    let store = h
        .open(
            config.clone(),
            Some(Scan::Rejected),
            Some(policy(8, 8, 8, 2)),
        )
        .expect("private retention store");
    let older_input = request(
        TenantId::new(),
        SessionId::new(),
        b"old!",
        ArtifactContentSource::ClientUpload,
    );
    assert_eq!(store.store(&older_input), Err(DependencyError::Rejected));
    let older_payload = h
        .payloads(older_input.key())
        .pop()
        .expect("older private bytes");
    let older = commits(&store).pop().expect("older original notification");
    assert_state(&older, &older_input, NotificationArtifactState::Quarantined);
    assert_eq!(older.occurred_at_unix_ms(), START);

    // Different tenant scopes permit a positive ACK for newer authority while older delivery waits.
    h.clock.set(START + 200);
    let newer_input = request(
        TenantId::new(),
        SessionId::new(),
        b"new!",
        ArtifactContentSource::BrowserDownload,
    );
    assert_eq!(store.store(&newer_input), Err(DependencyError::Rejected));
    let newer_payload = h
        .payloads(newer_input.key())
        .pop()
        .expect("newer private bytes");
    let newer = commits(&store)
        .into_iter()
        .find(|commit| commit.scope().tenant_id() == newer_input.key().tenant_id())
        .expect("independent newer notification");
    assert_state(&newer, &newer_input, NotificationArtifactState::Quarantined);
    assert_ne!(older.scope(), newer.scope());
    assert_eq!(newer.occurred_at_unix_ms(), START + 200);
    let newer_tombstone = quarantine_key(h.root.path(), newer_input.key()).join(format!(
        ".deleted-{}",
        hex::encode(generation(&newer_payload).as_bytes())
    ));
    store
        .acknowledge_notifications(&newer.ack())
        .expect("ACK newer scope only");
    h.clock.set(START + 301);
    settle(&store, 1);
    assert!(!newer_payload.exists());
    assert!(newer_tombstone.join("receipt").is_file());
    assert!(older_payload.exists());
    assert_eq!(commits(&store), vec![older.clone()]);

    // Advance the retirement watermark beyond the older admission and force real compaction.
    h.clock.set(START + 301 + DAY + 1);
    let mut retired = 0;
    for _ in 0..16 {
        let report = store
            .maintain(1)
            .expect("bounded retry retirement and compaction");
        assert!(report.scanned <= 1);
        retired += report.retired;
    }
    assert!(
        retired > 0,
        "newer terminal retry authority must actually retire"
    );
    assert!(
        !newer_tombstone.exists(),
        "newer positive deletion receipt is retired"
    );
    assert!(older_payload.exists());
    assert_eq!(commits(&store), vec![older.clone()]);
    drop(store);

    let store = h.open(config, None, None).expect(
        "compacted checkpoint restores older pending authority below the newer retirement watermark",
    );
    assert_eq!(commits(&store), vec![older.clone()]);
    assert_eq!(
        std::fs::read(&older_payload).expect("older exact bytes"),
        b"old!"
    );
    store
        .acknowledge_notifications(&newer.ack())
        .expect("permanent newer ACK survives retirement and compaction");
    let capacity = request(
        TenantId::new(),
        SessionId::new(),
        b"five!",
        ArtifactContentSource::Generated,
    );
    assert!(
        store.store(&capacity).is_err(),
        "older pending authority retains its charge after compaction"
    );
    settle(&store, 1);
    assert!(older_payload.exists());
    store
        .acknowledge_notifications(&older.ack())
        .expect("older original ACK remains authoritative");
    settle(&store, 1);
    assert!(!older_payload.exists());
    assert!(h.all_payloads().is_empty());
    assert!(commits(&store).is_empty());
    assert!(store.store(&capacity).is_ok());
    assert_eq!(h.scanner_calls.load(Ordering::SeqCst), 2);
}
