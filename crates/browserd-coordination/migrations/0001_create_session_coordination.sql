CREATE TABLE IF NOT EXISTS browserd_create_session_operations (
    tenant_id UUID NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    operation_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'accepted',
            'queued',
            'reserving',
            'creating',
            'succeeded',
            'timed_out',
            'cancelled',
            'failed'
        )
    ),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    result JSONB,
    operation_error JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL CHECK (
        retain_until >= created_at + INTERVAL '24 hours'
    ),
    PRIMARY KEY (tenant_id, idempotency_key),
    UNIQUE (tenant_id, operation_id),
    CHECK (
        (state = 'succeeded' AND result IS NOT NULL AND operation_error IS NULL)
        OR (state IN ('failed', 'timed_out') AND result IS NULL AND operation_error IS NOT NULL)
        OR (state NOT IN ('succeeded', 'failed', 'timed_out') AND result IS NULL AND operation_error IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS browserd_create_session_operations_retention_idx
    ON browserd_create_session_operations (retain_until)
    WHERE state IN ('succeeded', 'timed_out', 'cancelled', 'failed');
