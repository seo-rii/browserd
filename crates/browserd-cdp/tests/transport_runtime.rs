use std::time::Duration;

use browserd_cdp::{CdpCommandError, CdpTransport, CdpTransportConfig, CdpTransportError};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

async fn read_command(stream: &mut DuplexStream) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).await;
        assert!(read.is_ok());
        let Ok(read) = read else {
            return Value::Null;
        };
        if read == 0 || byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    let decoded = serde_json::from_slice(&bytes);
    assert!(decoded.is_ok());
    decoded.unwrap_or(Value::Null)
}

async fn write_message(stream: &mut DuplexStream, value: Value) {
    let encoded = serde_json::to_vec(&value);
    assert!(encoded.is_ok());
    if let Ok(encoded) = encoded {
        assert!(stream.write_all(&encoded).await.is_ok());
        assert!(stream.write_all(&[0]).await.is_ok());
    }
}

fn config() -> CdpTransportConfig {
    CdpTransportConfig {
        max_frame_bytes: 64 * 1024,
        max_pending_commands: 64,
        command_queue_capacity: 64,
        event_queue_capacity: 4,
        write_timeout: Duration::from_secs(1),
        default_command_timeout: Duration::from_secs(1),
    }
}

#[tokio::test]
async fn split_chromium_pipes_dispatch_commands_and_receive_messages() {
    let (driver_event_io, mut chromium_event_io) = tokio::io::duplex(16 * 1024);
    let (mut chromium_command_io, driver_command_io) = tokio::io::duplex(16 * 1024);
    let (event_reader, unused_event_writer) = tokio::io::split(driver_event_io);
    let (unused_command_reader, command_writer) = tokio::io::split(driver_command_io);
    drop(unused_event_writer);
    drop(unused_command_reader);

    let (client, mut events, driver) =
        CdpTransport::spawn_split(event_reader, command_writer, config());
    let command = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command("Browser.getVersion", json!({}), None, None)
                .await
        })
    };

    let dispatched = read_command(&mut chromium_command_io).await;
    let id = dispatched["id"].as_u64();
    assert!(id.is_some());
    write_message(
        &mut chromium_event_io,
        json!({"method": "Target.targetCreated", "params": {"targetInfo": {"targetId": "page"}}}),
    )
    .await;
    if let Some(id) = id {
        write_message(
            &mut chromium_event_io,
            json!({"id": id, "result": {"product": "Chromium"}}),
        )
        .await;
    }

    assert!(matches!(
        events.recv().await,
        Some(browserd_cdp::CdpIncoming::Event { method, .. })
            if method == "Target.targetCreated"
    ));
    let command = command.await;
    assert!(matches!(command, Ok(Ok(_))));
    if let Ok(Ok(result)) = command {
        assert_eq!(result, json!({"product": "Chromium"}));
    }
    driver.shutdown().await;
}

#[tokio::test]
async fn concurrent_commands_correlate_out_of_order_responses_exactly_once() {
    let (client_io, mut chromium_io) = tokio::io::duplex(64 * 1024);
    let (client, mut events, driver) = CdpTransport::spawn(client_io, config());
    let first = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command("Runtime.evaluate", json!({"expression": "1"}), None, None)
                .await
        })
    };
    let second = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command(
                    "Runtime.evaluate",
                    json!({"expression": "2"}),
                    Some("cdp-session".to_owned()),
                    None,
                )
                .await
        })
    };

    let command_a = read_command(&mut chromium_io).await;
    let command_b = read_command(&mut chromium_io).await;
    let id_a = command_a["id"].as_u64();
    let id_b = command_b["id"].as_u64();
    assert!(id_a.is_some());
    assert!(id_b.is_some());
    if let (Some(id_a), Some(id_b)) = (id_a, id_b) {
        write_message(
            &mut chromium_io,
            json!({"id": id_b, "result": {"value": command_b["params"]["expression"]}, "sessionId": command_b.get("sessionId")}),
        )
        .await;
        write_message(
            &mut chromium_io,
            json!({"id": id_a, "result": {"value": command_a["params"]["expression"]}}),
        )
        .await;
    }

    let first = first.await;
    let second = second.await;
    assert!(first.is_ok());
    assert!(second.is_ok());
    if let (Ok(Ok(first)), Ok(Ok(second))) = (first, second) {
        let mut values = [first["value"].clone(), second["value"].clone()];
        values.sort_by_key(Value::to_string);
        assert_eq!(values, [json!("1"), json!("2")]);
    }
    assert!(events.try_recv().is_err());
    driver.shutdown().await;
}

#[tokio::test]
async fn command_timeout_retires_the_id_and_late_response_is_not_reused() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let (client, _events, driver) = CdpTransport::spawn(client_io, config());
    let timed_out = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command(
                    "Page.navigate",
                    json!({"url": "https://example.com"}),
                    None,
                    Some(Duration::from_millis(20)),
                )
                .await
        })
    };
    let first_command = read_command(&mut chromium_io).await;
    let first_id = first_command["id"].as_u64();
    tokio::time::sleep(Duration::from_millis(40)).await;
    let timed_out = timed_out.await;
    assert!(matches!(timed_out, Ok(Err(CdpCommandError::TimedOut))));

    if let Some(first_id) = first_id {
        write_message(
            &mut chromium_io,
            json!({"id": first_id, "result": {"late": true}}),
        )
        .await;
    }
    let next = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command("Browser.getVersion", json!({}), None, None)
                .await
        })
    };
    let next_command = read_command(&mut chromium_io).await;
    let next_id = next_command["id"].as_u64();
    assert_ne!(first_id, next_id);
    if let Some(next_id) = next_id {
        write_message(
            &mut chromium_io,
            json!({"id": next_id, "result": {"product": "Chromium"}}),
        )
        .await;
    }
    let next = next.await;
    assert!(matches!(next, Ok(Ok(_))));
    driver.shutdown().await;
}

#[tokio::test]
async fn zero_command_timeout_is_rejected_before_any_dispatch() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let (client, _events, driver) = CdpTransport::spawn(client_io, config());

    let outcome = client
        .command(
            "Page.navigate",
            json!({"url": "https://example.com"}),
            None,
            Some(Duration::ZERO),
        )
        .await;
    assert_eq!(outcome, Err(CdpCommandError::TimedOut));

    let mut observed = [0_u8; 1];
    let read =
        tokio::time::timeout(Duration::from_millis(20), chromium_io.read(&mut observed)).await;
    assert!(read.is_err());
    driver.shutdown().await;
}

#[tokio::test]
async fn protocol_errors_remain_typed_and_do_not_desynchronize_other_commands() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let (client, _events, driver) = CdpTransport::spawn(client_io, config());
    let command = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .command("DOM.noSuchMethod", json!({}), None, None)
                .await
        })
    };
    let incoming = read_command(&mut chromium_io).await;
    if let Some(id) = incoming["id"].as_u64() {
        write_message(
            &mut chromium_io,
            json!({"id": id, "error": {"code": -32601, "message": "method not found"}}),
        )
        .await;
    }
    let outcome = command.await;
    assert!(matches!(
        outcome,
        Ok(Err(CdpCommandError::Protocol(error))) if error.code == -32601
    ));
    driver.shutdown().await;
}

#[tokio::test]
async fn event_queue_overflow_closes_the_transport_instead_of_growing_memory() {
    let (client_io, mut chromium_io) = tokio::io::duplex(64 * 1024);
    let mut constrained = config();
    constrained.event_queue_capacity = 1;
    let (client, _events, driver) = CdpTransport::spawn(client_io, constrained);

    write_message(
        &mut chromium_io,
        json!({"method": "Page.frameNavigated", "params": {"n": 1}}),
    )
    .await;
    write_message(
        &mut chromium_io,
        json!({"method": "Page.frameNavigated", "params": {"n": 2}}),
    )
    .await;

    let terminal = driver.wait().await;
    assert_eq!(terminal, Err(CdpTransportError::EventQueueOverflow));
    assert!(matches!(
        client
            .command("Browser.getVersion", json!({}), None, None)
            .await,
        Err(CdpCommandError::TransportClosed)
    ));
}

#[tokio::test]
async fn oversized_or_invalid_frames_close_all_pending_commands() {
    for invalid in [vec![b'x'; 257], b"not-json\0".to_vec()] {
        let (client_io, mut chromium_io) = tokio::io::duplex(4 * 1024);
        let mut constrained = config();
        constrained.max_frame_bytes = 256;
        let (client, _events, driver) = CdpTransport::spawn(client_io, constrained);
        let pending = {
            let client = client.clone();
            tokio::spawn(async move { client.command("Page.enable", json!({}), None, None).await })
        };
        let _command = read_command(&mut chromium_io).await;
        assert!(chromium_io.write_all(&invalid).await.is_ok());
        let terminal = driver.wait().await;
        assert!(matches!(terminal, Err(CdpTransportError::Protocol(_))));
        let pending = pending.await;
        assert!(matches!(pending, Ok(Err(CdpCommandError::TransportClosed))));
    }
}

#[tokio::test]
async fn pending_and_submission_queues_are_bounded_under_concurrency() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let mut constrained = config();
    constrained.max_pending_commands = 1;
    constrained.command_queue_capacity = 1;
    let (client, _events, driver) = CdpTransport::spawn(client_io, constrained);
    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.command("Page.enable", json!({}), None, None).await })
    };
    let first_command = read_command(&mut chromium_io).await;
    assert!(first_command["id"].is_u64());

    let second = client
        .command(
            "Runtime.enable",
            json!({}),
            None,
            Some(Duration::from_millis(50)),
        )
        .await;
    assert_eq!(second, Err(CdpCommandError::PendingLimitExceeded));
    driver.shutdown().await;
    let first = first.await;
    assert!(matches!(first, Ok(Err(CdpCommandError::TransportClosed))));
}

#[tokio::test]
async fn explicit_shutdown_fails_pending_work_and_completes_once() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let (client, _events, driver) = CdpTransport::spawn(client_io, config());
    let pending =
        tokio::spawn(async move { client.command("Page.enable", json!({}), None, None).await });
    let _command = read_command(&mut chromium_io).await;

    driver.shutdown().await;
    let pending = pending.await;
    assert!(matches!(pending, Ok(Err(CdpCommandError::TransportClosed))));
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_all_command_clients_does_not_starve_events_or_shutdown() {
    let (client_io, mut chromium_io) = tokio::io::duplex(16 * 1024);
    let (client, mut events, driver) = CdpTransport::spawn(client_io, config());
    drop(client);

    write_message(
        &mut chromium_io,
        json!({"method": "Page.lifecycleEvent", "params": {"name": "load"}}),
    )
    .await;
    let event = tokio::time::timeout(Duration::from_millis(100), events.recv()).await;
    assert!(matches!(
        event,
        Ok(Some(browserd_cdp::CdpIncoming::Event { method, .. }))
            if method == "Page.lifecycleEvent"
    ));

    let shutdown = tokio::time::timeout(Duration::from_millis(100), driver.shutdown()).await;
    assert!(shutdown.is_ok());
}
