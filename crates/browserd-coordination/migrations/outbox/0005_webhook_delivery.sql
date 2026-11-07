-- Separate migrator table: _browserd_webhook_migrations. Outbox owns versions 1..4.
CREATE TABLE browserd_webhook_namespace (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    config_sha256 BYTEA CHECK (config_sha256 IS NULL OR octet_length(config_sha256)=32),
    endpoint_count BIGINT NOT NULL DEFAULT 0 CHECK(endpoint_count>=0)
);
INSERT INTO browserd_webhook_namespace(singleton) VALUES(TRUE);
CREATE TABLE browserd_webhook_authority (
    tenant_id UUID PRIMARY KEY,
    -- Strict bounded versioned metadata, one pending payload and bounded redacted audits.
    state_json TEXT NOT NULL CHECK (octet_length(state_json)<=33554432)
);
CREATE TABLE browserd_webhook_ack_payload (
    tenant_id UUID NOT NULL REFERENCES browserd_webhook_authority(tenant_id),
    attempt_id UUID NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 524288),
    payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256)=32),
    acknowledged_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>acknowledged_at),
    PRIMARY KEY(tenant_id,attempt_id)
);
