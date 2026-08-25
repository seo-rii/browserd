#![allow(clippy::expect_used)]

use browserd_observability::{
    FieldSensitivity, HostRedaction, LogField, MetricLabelError, MetricLabelPolicy, UrlRedactor,
    redact_log_fields,
};

#[test]
fn url_redaction_omits_userinfo_path_query_fragment_and_raw_host() {
    let redactor = UrlRedactor::new(HostRedaction::Hash);
    let redacted = redactor
        .redact("https://alice:password@private.example:8443/orders/secret-id?token=hunter2#card")
        .expect("URL should parse");
    let rendered = format!("{redacted:?}");

    assert_eq!(redacted.scheme(), "https");
    assert_eq!(redacted.port(), Some(8443));
    assert_eq!(redacted.host(), None);
    assert!(redacted.host_hash().is_some());
    assert!(redacted.path_hash().is_some());
    for secret in [
        "alice",
        "password",
        "private.example",
        "orders",
        "secret-id",
        "token",
        "hunter2",
        "card",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn structured_secret_fields_are_redacted_even_when_misclassified_public() {
    let fields = redact_log_fields([
        LogField::new("event", "action.started", FieldSensitivity::Public),
        LogField::new(
            "Authorization",
            "Bearer secret-token",
            FieldSensitivity::Public,
        ),
        LogField::new("cookie", "sid=secret-cookie", FieldSensitivity::Secret),
        LogField::new("form_value", "4111111111111111", FieldSensitivity::Secret),
        LogField::new("resolved_secret", "api-key-value", FieldSensitivity::Secret),
        LogField::new("api_key", "misclassified-api-key", FieldSensitivity::Public),
    ]);
    let rendered = format!("{fields:?}");

    assert!(rendered.contains("action.started"));
    for secret in [
        "Bearer secret-token",
        "sid=secret-cookie",
        "4111111111111111",
        "api-key-value",
        "misclassified-api-key",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert_eq!(fields.value("Authorization"), Some("[REDACTED]"));
}

#[test]
fn metric_policy_rejects_identifiers_and_unbounded_request_dimensions() {
    for forbidden in [
        "tenant_id",
        "session_id",
        "action_id",
        "operation_id",
        "principal_id",
        "request_id",
        "trace_id",
        "artifact_id",
        "page_id",
        "url",
        "host",
        "path",
    ] {
        assert_eq!(
            MetricLabelPolicy::validate(["status", forbidden]),
            Err(MetricLabelError::HighCardinalityLabel(forbidden.into()))
        );
    }
    assert!(
        MetricLabelPolicy::validate([
            "type",
            "status",
            "reason",
            "isolation",
            "network_class",
            "workload_class",
        ])
        .is_ok()
    );
    assert_eq!(
        MetricLabelPolicy::validate(["status", "customer_email"]),
        Err(MetricLabelError::HighCardinalityLabel(
            "customer_email".into()
        ))
    );
}
