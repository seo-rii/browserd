//! Privacy-safe observability, durable audit spooling, and usage aggregation.

mod audit;
mod redaction;
mod usage;

pub use audit::{
    AckOutcome, AppendOutcome, AuditEvent, AuditEventId, AuditSequence, AuditWal, AuditWalError,
    AuditWalPolicy, PendingAuditEvent,
};
pub use redaction::{
    FieldSensitivity, HostRedaction, LogField, MetricLabelError, MetricLabelPolicy,
    RedactedLogFields, RedactedUrl, RedactionError, UrlRedactor, redact_log_fields,
};
pub use usage::{
    UsageAggregator, UsageDimension, UsageEvent, UsageEventId, UsageRecordError, UsageRecordOutcome,
};
