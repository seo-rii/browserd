#![allow(clippy::expect_used)]

use browserd_worker::ViewerClientMessage;

#[test]
fn viewer_message_contract_rejects_unknown_fields_and_unbounded_input() {
    for invalid in [
        serde_json::json!({"type":"ping","lease_epoch":1}),
        serde_json::json!({"type":"release_control","lease_epoch":1}),
        serde_json::json!({"type":"request_control","force":false,"page_id":"untrusted"}),
        serde_json::json!({"type":"resize_view_only","width":0,"height":100}),
        serde_json::json!({"type":"resize_view_only","width":100_000,"height":100}),
        serde_json::json!({"type":"ack","frame_id":"-1"}),
        serde_json::json!({"type":"insert_text","lease_epoch":0,"input_sequence":1,
            "page_id":"page_invalid","frame_transform_id":1,"text":"x"}),
    ] {
        let accepted = serde_json::from_value::<ViewerClientMessage>(invalid.clone())
            .is_ok_and(|message| message.is_valid());
        assert!(!accepted, "invalid viewer input was accepted: {invalid}");
    }
}

#[test]
fn viewer_message_contract_accepts_existing_browser_client_messages() {
    for message in [
        serde_json::json!({"type":"ping"}),
        serde_json::json!({"type":"ack","frame_id":"42"}),
        serde_json::json!({"type":"request_control","force":false}),
        serde_json::json!({"type":"release_control"}),
        serde_json::json!({"type":"resize_view_only","width":1920,"height":1080}),
    ] {
        let parsed: ViewerClientMessage = serde_json::from_value(message).expect("client message");
        assert!(parsed.is_valid());
    }
}

#[test]
fn viewer_input_has_bounded_coordinates_text_and_javascript_safe_fences() {
    let page_id = browserd_core::PageId::new();
    let valid = serde_json::json!({
        "type":"mouse", "lease_epoch":1,"input_sequence":2,"page_id":page_id,
        "frame_transform_id":3,"phase":"down","button":"left","buttons":1,
        "x":12.5,"y":23.75
    });
    let input: ViewerClientMessage = serde_json::from_value(valid.clone()).expect("valid mouse");
    assert!(input.is_valid());
    assert_eq!(input.input_meta(), Some((1, 2, &page_id, 3)));
    assert!(matches!(
        input.input_kind(),
        Some(browserd_viewer::InputKind::MouseDown(0))
    ));
    for (field, value) in [
        ("x", serde_json::json!(-1)),
        ("y", serde_json::json!(1e100)),
        ("buttons", serde_json::json!(255)),
        ("lease_epoch", serde_json::json!(9_007_199_254_740_992_u64)),
        ("input_sequence", serde_json::json!(0)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(
            !serde_json::from_value::<ViewerClientMessage>(invalid)
                .is_ok_and(|message| message.is_valid()),
            "accepted {field}"
        );
    }
    let too_long = serde_json::json!({
        "type":"insert_text","lease_epoch":1,"input_sequence":1,"page_id":page_id,
        "frame_transform_id":1,"text":"x".repeat(16_385)
    });
    assert!(
        !serde_json::from_value::<ViewerClientMessage>(too_long)
            .is_ok_and(|message| message.is_valid())
    );
}
