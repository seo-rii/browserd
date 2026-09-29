-- Durable event outbox (BRD-017 / BRD-003): the per-tenant, ordered log of terminal transitions
-- for at-least-once notification, plus a per-tenant cursor row carrying the sequence counter and
-- the delivered/pruned watermarks.

CREATE TABLE IF NOT EXISTS browserd_event_outbox_cursor (
    tenant_id UUID PRIMARY KEY,
    next_seq BIGINT NOT NULL DEFAULT 0 CHECK (next_seq >= 0),
    delivered_through BIGINT NOT NULL DEFAULT 0 CHECK (delivered_through >= 0),
    pruned_through BIGINT NOT NULL DEFAULT 0 CHECK (pruned_through >= 0),
    CHECK (delivered_through <= next_seq),
    CHECK (pruned_through <= next_seq)
);

CREATE TABLE IF NOT EXISTS browserd_event_outbox (
    tenant_id UUID NOT NULL,
    tenant_seq BIGINT NOT NULL CHECK (tenant_seq >= 1),
    event_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('action_terminal', 'session_lost')),
    session_id UUID NOT NULL,
    action_id UUID,
    aggregate_revision BIGINT NOT NULL CHECK (aggregate_revision >= 0),
    dedup_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    -- An action-terminal event names an action; a session-lost event does not.
    CHECK (
        (kind = 'action_terminal' AND action_id IS NOT NULL)
        OR (kind = 'session_lost' AND action_id IS NULL)
    ),
    PRIMARY KEY (tenant_id, tenant_seq),
    -- Idempotency: one event per (aggregate, revision, kind), so a re-driven terminal commit does
    -- not append a duplicate.
    UNIQUE (tenant_id, dedup_key),
    -- Stable delivery identity, for resuming a consumer by opaque event id.
    UNIQUE (tenant_id, event_id)
);

-- Age-based retention pruning scans the oldest events per tenant.
CREATE INDEX IF NOT EXISTS browserd_event_outbox_retention_idx
    ON browserd_event_outbox (tenant_id, created_at);
