-- Public occurrence time and retention time have different authorities for delayed relays.
-- NULL retains the exact legacy append semantics; source imports set their durable commit time.
ALTER TABLE browserd_event_outbox ADD COLUMN retention_started_at TIMESTAMPTZ;
CREATE INDEX browserd_event_outbox_import_retention_idx
    ON browserd_event_outbox (tenant_id, COALESCE(retention_started_at, created_at));

-- Immutable lifetime quota; these counts and source identities are never payload-GC targets.
CREATE TABLE browserd_notification_import_namespace (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    config_sha256 BYTEA CHECK (octet_length(config_sha256) = 32),
    source_count BIGINT NOT NULL DEFAULT 0 CHECK (source_count >= 0),
    CHECK (config_sha256 IS NOT NULL OR source_count = 0)
);
INSERT INTO browserd_notification_import_namespace (singleton) VALUES (TRUE);

CREATE TABLE browserd_notification_source_watermark (
    tenant_id UUID NOT NULL,
    original_worker_id TEXT NOT NULL CHECK (octet_length(original_worker_id) BETWEEN 1 AND 255),
    source_id UUID NOT NULL CHECK (source_id <> '00000000-0000-0000-0000-000000000000'),
    family TEXT NOT NULL CHECK (family IN ('action_journal', 'artifact_registry', 'session_lifecycle', 'control_journal')),
    imported_through BIGINT NOT NULL CHECK (imported_through > 0),
    PRIMARY KEY (tenant_id, original_worker_id, source_id, family)
);

-- Fixed-size 64-entry lookback per stream. Pruning events never touches these exact ACK receipts.
CREATE TABLE browserd_notification_import_receipt (
    tenant_id UUID NOT NULL,
    original_worker_id TEXT NOT NULL,
    source_id UUID NOT NULL,
    family TEXT NOT NULL,
    source_sequence BIGINT NOT NULL CHECK (source_sequence > 0),
    commit_sha256 BYTEA NOT NULL CHECK (octet_length(commit_sha256) = 32),
    PRIMARY KEY (tenant_id, original_worker_id, source_id, family, source_sequence),
    FOREIGN KEY (tenant_id, original_worker_id, source_id, family)
        REFERENCES browserd_notification_source_watermark (tenant_id, original_worker_id, source_id, family)
);
