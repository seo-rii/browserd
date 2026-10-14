-- Existing terminal projections retain their permanent watermarks during the namespace upgrade.
ALTER TABLE browserd_event_projection_watermark
    ADD COLUMN source TEXT NOT NULL DEFAULT 'terminal'
    CHECK (source IN ('terminal', 'viewer_control'));
ALTER TABLE browserd_event_projection_watermark
    DROP CONSTRAINT browserd_event_projection_watermark_pkey;
ALTER TABLE browserd_event_projection_watermark
    ADD PRIMARY KEY (tenant_id, session_id, source);

ALTER TABLE browserd_event_outbox DROP CONSTRAINT browserd_event_outbox_kind_check;
ALTER TABLE browserd_event_outbox DROP CONSTRAINT browserd_event_outbox_check;
ALTER TABLE browserd_event_outbox ADD CHECK (kind IN ('action_terminal', 'session_lost', 'control_changed'));
ALTER TABLE browserd_event_outbox ADD CHECK (
    (kind = 'action_terminal' AND action_id IS NOT NULL)
    OR (kind IN ('session_lost', 'control_changed') AND action_id IS NULL)
);
