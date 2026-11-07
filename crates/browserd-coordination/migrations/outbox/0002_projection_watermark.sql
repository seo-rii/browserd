-- A source session owns one immutable contiguous projection sequence. Keep its sink highwater
-- after notification payload retention so lost source acknowledgements cannot resurrect events.
-- These rows share the source permanent session-fence lifetime; do not apply payload TTL/GC.
CREATE TABLE IF NOT EXISTS browserd_event_projection_watermark (
    tenant_id UUID NOT NULL,
    session_id UUID NOT NULL,
    projected_through BIGINT NOT NULL CHECK (projected_through >= 1),
    PRIMARY KEY (tenant_id, session_id)
);
