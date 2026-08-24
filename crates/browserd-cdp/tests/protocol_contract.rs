#![allow(clippy::expect_used)]

use browserd_cdp::{
    BoundedEventQueue, CdpCommand, CdpError, CdpFrameCodec, CdpIncoming, PendingRegistry,
    ResolveOutcome,
};
use bytes::{Bytes, BytesMut};
use serde_json::json;
use tokio_util::codec::{Decoder, Encoder};

#[test]
fn debugging_pipe_frames_are_nul_terminated_and_bounded() {
    let mut codec = CdpFrameCodec::new(256);
    let mut destination = BytesMut::new();
    codec
        .encode(
            CdpCommand::new(7, "Page.navigate", json!({"url": "https://example.com"}))
                .with_session_id("target-session"),
            &mut destination,
        )
        .expect("bounded command must encode");

    assert_eq!(destination.last(), Some(&0));
    let encoded: serde_json::Value = serde_json::from_slice(&destination[..destination.len() - 1])
        .expect("encoded frame must be JSON");
    assert_eq!(encoded["id"], 7);
    assert_eq!(encoded["method"], "Page.navigate");
    assert_eq!(encoded["sessionId"], "target-session");

    let mut too_small = CdpFrameCodec::new(16);
    let error = too_small
        .encode(
            CdpCommand::new(1, "Runtime.evaluate", json!({"expression": "x".repeat(64)})),
            &mut BytesMut::new(),
        )
        .expect_err("oversized commands must be rejected before writing");
    assert!(matches!(error, CdpError::FrameTooLarge { .. }));
}

#[test]
fn decoder_waits_for_fragment_completion_and_classifies_messages() {
    let mut codec = CdpFrameCodec::new(1_024);
    let mut fragmented = BytesMut::from(
        &b"{\"method\":\"Page.frameNavigated\",\"params\":{\"frame\":{\"id\":\"f\"}}"[..],
    );
    assert_eq!(codec.decode(&mut fragmented), Ok(None));
    fragmented.extend_from_slice(b",\"sessionId\":\"s\"}\0");

    assert_eq!(
        codec.decode(&mut fragmented),
        Ok(Some(CdpIncoming::Event {
            method: "Page.frameNavigated".to_owned(),
            params: json!({"frame": {"id": "f"}}),
            session_id: Some("s".to_owned()),
        }))
    );

    let mut response = BytesMut::from(&b"{\"id\":9,\"result\":{\"value\":42}}\0"[..]);
    assert_eq!(
        codec.decode(&mut response),
        Ok(Some(CdpIncoming::Response {
            id: 9,
            result: json!({"value": 42}),
            session_id: None,
        }))
    );

    let mut protocol_error = BytesMut::from(
        &b"{\"id\":10,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}\0"[..],
    );
    assert!(matches!(
        codec.decode(&mut protocol_error),
        Ok(Some(CdpIncoming::ProtocolError { id: 10, .. }))
    ));
}

#[test]
fn malformed_and_unterminated_oversized_frames_fail_closed() {
    let mut codec = CdpFrameCodec::new(32);
    let mut unterminated = BytesMut::from(&vec![b'x'; 33][..]);
    assert!(matches!(
        codec.decode(&mut unterminated),
        Err(CdpError::FrameTooLarge { .. })
    ));
    assert!(codec.is_desynchronized());

    let mut codec = CdpFrameCodec::new(64);
    let mut malformed = BytesMut::from(&b"not-json\0"[..]);
    assert!(matches!(
        codec.decode(&mut malformed),
        Err(CdpError::InvalidJson)
    ));
    assert!(codec.is_desynchronized());

    let mut codec = CdpFrameCodec::new(64);
    let mut unknown = BytesMut::from(&b"{\"unexpected\":true}\0"[..]);
    assert!(matches!(
        codec.decode(&mut unknown),
        Err(CdpError::InvalidEnvelope)
    ));
}

#[test]
fn pending_registry_bounds_commands_and_treats_duplicates_as_late() {
    let mut pending = PendingRegistry::new(2);
    let first = pending
        .register("Page.navigate")
        .expect("first slot must fit");
    let second = pending
        .register("Runtime.evaluate")
        .expect("second slot must fit");
    assert_ne!(first.id(), second.id());
    assert_eq!(pending.len(), 2);
    assert!(matches!(
        pending.register("Page.captureScreenshot"),
        Err(CdpError::PendingLimitExceeded { limit: 2 })
    ));

    assert_eq!(
        pending.resolve(first.id()),
        ResolveOutcome::Matched {
            method: "Page.navigate".to_owned()
        }
    );
    assert_eq!(pending.resolve(first.id()), ResolveOutcome::LateOrDuplicate);
    assert_eq!(pending.late_responses(), 1);
    assert_eq!(pending.len(), 1);

    let abandoned = pending.close();
    assert_eq!(abandoned.len(), 1);
    assert_eq!(abandoned[0].id(), second.id());
    assert!(matches!(
        pending.register("Page.reload"),
        Err(CdpError::TransportClosed)
    ));
}

#[test]
fn event_queue_overflow_marks_the_transport_desynchronized_instead_of_dropping_silently() {
    let mut queue = BoundedEventQueue::new(2);
    queue
        .push(CdpIncoming::Event {
            method: "Target.attachedToTarget".to_owned(),
            params: json!({"n": 1}),
            session_id: None,
        })
        .expect("first event must fit");
    queue
        .push(CdpIncoming::Event {
            method: "Target.targetCreated".to_owned(),
            params: json!({"n": 2}),
            session_id: None,
        })
        .expect("second event must fit");

    assert!(matches!(
        queue.push(CdpIncoming::Event {
            method: "Target.targetInfoChanged".to_owned(),
            params: json!({"n": 3}),
            session_id: None,
        }),
        Err(CdpError::EventQueueOverflow { capacity: 2 })
    ));
    assert!(queue.is_desynchronized());
    assert!(matches!(
        queue.push(CdpIncoming::Event {
            method: "Page.loadEventFired".to_owned(),
            params: json!({}),
            session_id: None,
        }),
        Err(CdpError::TransportDesynchronized)
    ));

    assert!(
        queue.pop().is_none(),
        "untrusted queued events must be discarded"
    );
}

#[test]
fn decoder_accepts_multiple_complete_frames_without_overreading() {
    let mut codec = CdpFrameCodec::new(128);
    let mut source = BytesMut::from(
        &b"{\"method\":\"A\",\"params\":{}}\0{\"method\":\"B\",\"params\":{}}\0"[..],
    );

    let first = codec
        .decode(&mut source)
        .expect("first decode must succeed")
        .expect("first frame must exist");
    let second = codec
        .decode(&mut source)
        .expect("second decode must succeed")
        .expect("second frame must exist");

    assert!(matches!(first, CdpIncoming::Event { method, .. } if method == "A"));
    assert!(matches!(second, CdpIncoming::Event { method, .. } if method == "B"));
    assert_eq!(source, Bytes::new());
}
