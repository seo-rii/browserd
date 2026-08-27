#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use browserd_cdp::{CdpCommandError, CdpTransportConfig};
use browserd_chromium::{
    ChromiumArtifactIdentity, ChromiumConnection, ChromiumConnectionConfig,
    ChromiumConnectionError, Sha256Digest,
};
use browserd_sandbox::ChromiumCdpPipes;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};

fn identity() -> ChromiumArtifactIdentity {
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("test digest must be valid");
    ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "149.0.7827.55".to_owned(),
        chromium_revision: "r1234567".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

fn config() -> ChromiumConnectionConfig {
    ChromiumConnectionConfig {
        transport: CdpTransportConfig {
            max_frame_bytes: 64 * 1024,
            max_pending_commands: 16,
            command_queue_capacity: 16,
            event_queue_capacity: 16,
            write_timeout: Duration::from_millis(200),
            default_command_timeout: Duration::from_millis(200),
        },
        version_probe_timeout: Duration::from_millis(200),
        max_version_field_bytes: 1_024,
    }
}

fn pipe_pair() -> (ChromiumCdpPipes, Receiver, Sender) {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
    let parent = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
        .expect("parent capabilities should be valid");
    let command_reader =
        Receiver::from_owned_fd(command_reader).expect("command reader should become async");
    let event_writer =
        Sender::from_owned_fd(event_writer).expect("event writer should become async");
    (parent, command_reader, event_writer)
}

async fn read_command(reader: &mut Receiver) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .expect("command read should work");
        if read == 0 || byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).expect("command should be valid JSON")
}

async fn write_message(writer: &mut Sender, message: Value) {
    let bytes = serde_json::to_vec(&message).expect("message should encode");
    writer
        .write_all(&bytes)
        .await
        .expect("message body should write");
    writer
        .write_all(&[0])
        .await
        .expect("message terminator should write");
}

#[tokio::test]
async fn connects_real_chromium_pipes_and_verifies_the_pinned_version() {
    let expected = identity();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let connect_expected = expected.clone();
    let connect = tokio::spawn(async move {
        ChromiumConnection::connect(pipes, &connect_expected, config()).await
    });

    let command = read_command(&mut command_reader).await;
    assert_eq!(command["method"], "Browser.getVersion");
    assert_eq!(command["params"], json!({}));
    let id = command["id"].as_u64().expect("command ID should exist");
    write_message(
        &mut event_writer,
        json!({"method": "Target.targetCreated", "params": {"targetInfo": {"targetId": "page"}}}),
    )
    .await;
    write_message(
        &mut event_writer,
        json!({
            "id": id,
            "result": {
                "protocolVersion": "1.3",
                "product": "HeadlessChrome/149.0.7827.55",
                "revision": "r1234567",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }
        }),
    )
    .await;

    let connected = connect.await.expect("connect task should finish");
    assert!(connected.is_ok());
    let mut connection = connected.unwrap();
    assert_eq!(connection.version().product, "HeadlessChrome/149.0.7827.55");
    assert_eq!(connection.version().revision, expected.chromium_revision);
    assert!(matches!(
        connection.next_event().await,
        Some(browserd_cdp::CdpIncoming::Event { method, .. })
            if method == "Target.targetCreated"
    ));

    let command_round_trip = connection.command(
        "Browser.createBrowserContext",
        json!({"disposeOnDetach": true}),
        None,
        Some(Duration::from_millis(100)),
    );
    let chromium_round_trip = async {
        let command = read_command(&mut command_reader).await;
        assert_eq!(command["method"], "Browser.createBrowserContext");
        assert_eq!(command["params"], json!({"disposeOnDetach": true}));
        let id = command["id"].as_u64().expect("command ID should exist");
        write_message(
            &mut event_writer,
            json!({"id": id, "result": {"browserContextId": "context-1"}}),
        )
        .await;
    };
    let (result, ()) = tokio::join!(command_round_trip, chromium_round_trip);
    assert_eq!(
        result.expect("post-handshake command should succeed"),
        json!({"browserContextId": "context-1"})
    );
    connection.shutdown().await;

    let mut byte = [0_u8; 1];
    let eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(eof, Ok(Ok(0))));
}

#[tokio::test]
async fn verified_connection_splits_into_one_command_channel_one_event_stream_and_driver_owner() {
    let expected = identity();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let connect_expected = expected.clone();
    let connect = tokio::spawn(async move {
        ChromiumConnection::connect(pipes, &connect_expected, config()).await
    });
    let version = read_command(&mut command_reader).await;
    let id = version["id"].as_u64().expect("version command ID");
    write_message(
        &mut event_writer,
        json!({"id": id, "result": {
            "protocolVersion": "1.3", "product": "HeadlessChrome/149.0.7827.55",
            "revision": "r1234567", "userAgent": "test", "jsVersion": "14.9"
        }}),
    )
    .await;
    let connection = connect.await.expect("connect joins").expect("connects");
    let (client, mut events, owner) = connection.into_verified_parts();
    let command = tokio::spawn(async move {
        client
            .command("Target.getTargets", json!({}), None, None)
            .await
    });
    let get_targets = read_command(&mut command_reader).await;
    let command_id = get_targets["id"].as_u64().expect("target command ID");
    write_message(
        &mut event_writer,
        json!({"method":"Target.attachedToTarget","params":{}}),
    )
    .await;
    write_message(
        &mut event_writer,
        json!({"id":command_id,"result":{"targetInfos":[]}}),
    )
    .await;
    assert!(command.await.expect("command joins").is_ok());
    assert!(matches!(
        events.recv().await,
        Some(browserd_cdp::CdpIncoming::Event { .. })
    ));
    owner.shutdown().await;
}

#[tokio::test]
async fn rejects_product_version_or_revision_mismatch_and_closes_the_pipes() {
    for (product, revision, version_mismatch) in [
        ("HeadlessChrome/150.0.0.0", "r1234567", true),
        ("HeadlessChrome/149.0.7827.55", "r7654321", false),
    ] {
        let expected = identity();
        let (pipes, mut command_reader, mut event_writer) = pipe_pair();
        let connect =
            tokio::spawn(
                async move { ChromiumConnection::connect(pipes, &expected, config()).await },
            );
        let command = read_command(&mut command_reader).await;
        let id = command["id"].as_u64().expect("command ID should exist");
        write_message(
            &mut event_writer,
            json!({
                "id": id,
                "result": {
                    "protocolVersion": "1.3",
                    "product": product,
                    "revision": revision,
                    "userAgent": "browserd-test",
                    "jsVersion": "14.9"
                }
            }),
        )
        .await;

        let result = connect.await.expect("connect task should finish");
        if version_mismatch {
            assert!(matches!(
                result,
                Err(ChromiumConnectionError::ProductVersionMismatch { .. })
            ));
        } else {
            assert!(matches!(
                result,
                Err(ChromiumConnectionError::RevisionMismatch { .. })
            ));
        }
        let mut byte = [0_u8; 1];
        let eof =
            tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
        assert!(matches!(eof, Ok(Ok(0))));
        let closed =
            tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
        assert!(matches!(closed, Ok(Err(_))));
    }
}

#[tokio::test]
async fn rejects_missing_non_string_or_oversized_version_fields() {
    for (result, invalid_field) in [
        (
            json!({
                "protocolVersion": "1.3",
                "product": "HeadlessChrome/149.0.7827.55",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }),
            "revision",
        ),
        (
            json!({
                "protocolVersion": "1.3",
                "product": "HeadlessChrome/149.0.7827.55",
                "revision": 1234567,
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }),
            "revision",
        ),
        (
            json!({
                "protocolVersion": "1.3",
                "product": "x".repeat(2_048),
                "revision": "r1234567",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }),
            "product",
        ),
        (
            json!({
                "protocolVersion": "1.3",
                "product": "Browserd/149.0.7827.55",
                "revision": "r1234567",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }),
            "product",
        ),
        (
            json!({
                "protocolVersion": "",
                "product": "HeadlessChrome/149.0.7827.55",
                "revision": "r1234567",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }),
            "protocolVersion",
        ),
    ] {
        let expected = identity();
        let (pipes, mut command_reader, mut event_writer) = pipe_pair();
        let connect =
            tokio::spawn(
                async move { ChromiumConnection::connect(pipes, &expected, config()).await },
            );
        let command = read_command(&mut command_reader).await;
        let id = command["id"].as_u64().expect("command ID should exist");
        write_message(&mut event_writer, json!({"id": id, "result": result})).await;

        assert!(matches!(
            connect.await.expect("connect task should finish"),
            Err(ChromiumConnectionError::InvalidVersionField { field })
                if field == invalid_field
        ));
        let mut byte = [0_u8; 1];
        let eof =
            tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
        assert!(matches!(eof, Ok(Ok(0))));
        let closed =
            tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
        assert!(matches!(closed, Ok(Err(_))));
    }
}

#[tokio::test]
async fn chromium_eof_during_readiness_is_typed_and_bounded() {
    let expected = identity();
    let (pipes, mut command_reader, event_writer) = pipe_pair();
    let connect =
        tokio::spawn(async move { ChromiumConnection::connect(pipes, &expected, config()).await });
    let _command = read_command(&mut command_reader).await;
    drop(event_writer);

    let result = tokio::time::timeout(Duration::from_millis(100), connect).await;
    assert!(matches!(
        result,
        Ok(Ok(Err(ChromiumConnectionError::Command(
            CdpCommandError::TransportClosed
        ))))
    ));
    let mut byte = [0_u8; 1];
    let eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(eof, Ok(Ok(0))));
}

#[tokio::test]
async fn version_probe_has_an_absolute_timeout_and_closes_both_pipes() {
    let expected = identity();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let mut connection_config = config();
    connection_config.version_probe_timeout = Duration::from_millis(20);
    connection_config.transport.write_timeout = Duration::from_secs(1);
    connection_config.transport.default_command_timeout = Duration::from_secs(1);
    let connect = tokio::spawn(async move {
        ChromiumConnection::connect(pipes, &expected, connection_config).await
    });
    let _command = read_command(&mut command_reader).await;

    let result = tokio::time::timeout(Duration::from_millis(100), connect).await;
    assert!(matches!(
        result,
        Ok(Ok(Err(ChromiumConnectionError::VersionProbeTimedOut)))
    ));
    let mut byte = [0_u8; 1];
    let eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(eof, Ok(Ok(0))));
    let closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
    assert!(matches!(closed, Ok(Err(_))));
}

#[tokio::test]
async fn invalid_config_or_expected_identity_is_rejected_before_dispatch() {
    for invalid_identity in [false, true] {
        let mut expected = identity();
        let mut connection_config = config();
        if invalid_identity {
            expected.product_version.clear();
        } else {
            connection_config.max_version_field_bytes = 0;
        }
        let (pipes, mut command_reader, mut event_writer) = pipe_pair();

        let result = ChromiumConnection::connect(pipes, &expected, connection_config).await;

        if invalid_identity {
            assert!(matches!(
                result,
                Err(ChromiumConnectionError::InvalidExpectedIdentity {
                    field: "product_version"
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(ChromiumConnectionError::InvalidTransportConfig)
            ));
        }
        let mut byte = [0_u8; 1];
        let eof =
            tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
        assert!(matches!(eof, Ok(Ok(0))));
        let closed =
            tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
        assert!(matches!(closed, Ok(Err(_))));
    }
}

#[tokio::test]
async fn dropping_an_established_connection_closes_both_pipes() {
    let expected = identity();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let connect =
        tokio::spawn(async move { ChromiumConnection::connect(pipes, &expected, config()).await });
    let command = read_command(&mut command_reader).await;
    let id = command["id"].as_u64().expect("command ID should exist");
    write_message(
        &mut event_writer,
        json!({
            "id": id,
            "result": {
                "protocolVersion": "1.3",
                "product": "HeadlessChrome/149.0.7827.55",
                "revision": "r1234567",
                "userAgent": "browserd-test",
                "jsVersion": "14.9"
            }
        }),
    )
    .await;
    let connection = connect
        .await
        .expect("connect task should finish")
        .expect("connection should qualify");

    drop(connection);

    let mut byte = [0_u8; 1];
    let eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(eof, Ok(Ok(0))));
    let closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
    assert!(matches!(closed, Ok(Err(_))));
}

#[tokio::test]
async fn cancelling_connect_closes_both_uncommitted_capabilities() {
    let expected = identity();
    let (pipes, mut command_reader, mut event_writer) = pipe_pair();
    let connect =
        tokio::spawn(async move { ChromiumConnection::connect(pipes, &expected, config()).await });
    let _command = read_command(&mut command_reader).await;

    connect.abort();
    assert!(
        connect
            .await
            .expect_err("connect should be cancelled")
            .is_cancelled()
    );
    let mut byte = [0_u8; 1];
    let eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(eof, Ok(Ok(0))));
    let closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"{}\0")).await;
    assert!(matches!(closed, Ok(Err(_))));
}
