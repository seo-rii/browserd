-- Add immutable typed notifications without rewriting legacy event identities or watermarks.
ALTER TABLE browserd_event_outbox ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE browserd_event_outbox ADD COLUMN operation_id UUID;
ALTER TABLE browserd_event_outbox ADD COLUMN approval_id UUID;
ALTER TABLE browserd_event_outbox ADD COLUMN artifact_id UUID;
ALTER TABLE browserd_event_outbox ADD COLUMN state_summary JSONB;
ALTER TABLE browserd_event_outbox DROP CONSTRAINT browserd_event_outbox_kind_check;
ALTER TABLE browserd_event_outbox DROP CONSTRAINT browserd_event_outbox_check;
ALTER TABLE browserd_event_outbox ADD CONSTRAINT browserd_event_outbox_kind_check CHECK (kind IN (
    'action_terminal', 'session_lost', 'control_changed', 'operation_state_changed',
    'session_lifecycle_changed', 'session_execution_changed', 'action_state_changed',
    'action_approval_required', 'approval_decided', 'browser_control_changed',
    'download_completed', 'artifact_state_changed'
));
ALTER TABLE browserd_event_outbox ADD CONSTRAINT browserd_event_outbox_check CHECK (
    (kind = 'operation_state_changed' AND operation_id IS NOT NULL AND session_id IS NULL AND action_id IS NULL AND approval_id IS NULL AND artifact_id IS NULL)
    OR (kind IN ('session_lost', 'control_changed', 'session_lifecycle_changed', 'session_execution_changed', 'browser_control_changed') AND session_id IS NOT NULL AND operation_id IS NULL AND action_id IS NULL AND approval_id IS NULL AND artifact_id IS NULL)
    OR (kind IN ('action_terminal', 'action_state_changed', 'action_approval_required') AND session_id IS NOT NULL AND action_id IS NOT NULL AND operation_id IS NULL AND approval_id IS NULL AND artifact_id IS NULL)
    OR (kind = 'approval_decided' AND session_id IS NOT NULL AND action_id IS NOT NULL AND approval_id IS NOT NULL AND operation_id IS NULL AND artifact_id IS NULL)
    OR (kind IN ('download_completed', 'artifact_state_changed') AND session_id IS NOT NULL AND artifact_id IS NOT NULL AND operation_id IS NULL AND action_id IS NULL AND approval_id IS NULL)
);
ALTER TABLE browserd_event_outbox ADD CONSTRAINT browserd_event_outbox_summary_check CHECK (
    (kind IN ('action_terminal', 'session_lost', 'control_changed') AND state_summary IS NULL)
    OR (kind NOT IN ('action_terminal', 'session_lost', 'control_changed') AND state_summary IS NOT NULL
        AND jsonb_typeof(state_summary) = 'object' AND octet_length(state_summary::text) <= 32768
        AND state_summary ? 'type'
        AND state_summary->>'type' = CASE kind
            WHEN 'operation_state_changed' THEN 'operation'
            WHEN 'session_lifecycle_changed' THEN 'session_lifecycle'
            WHEN 'session_execution_changed' THEN 'session_execution'
            WHEN 'action_state_changed' THEN 'action'
            WHEN 'action_approval_required' THEN 'approval_required'
            WHEN 'approval_decided' THEN 'approval'
            WHEN 'browser_control_changed' THEN 'control'
            WHEN 'download_completed' THEN 'download'
            WHEN 'artifact_state_changed' THEN 'artifact'
        END)
);
-- Fail closed on missing/extra summary fields as well as unknown states. JSON null cannot use
-- SQL CHECK's NULL result to bypass these predicates; Rust additionally validates typed IDs.
ALTER TABLE browserd_event_outbox ADD CONSTRAINT browserd_event_outbox_summary_shape_check CHECK (
    state_summary IS NULL OR (CASE state_summary->>'type'
        WHEN 'operation' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND state_summary->>'state' IN ('accepted','queued','reserving','creating','succeeded','timed_out','cancelled','failed')
            AND ((aggregate_revision = 0) = (state_summary->>'state' = 'accepted'))
        WHEN 'session_lifecycle' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('creating','ready','closing','closed','failed')
        WHEN 'session_execution' THEN state_summary - ARRAY['type','state','action_id'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('idle','running','pending_approval','reconciliation_required')
            AND ((state_summary->>'state' = 'idle' AND state_summary->>'action_id' IS NULL)
                OR (state_summary->>'state' <> 'idle' AND jsonb_typeof(state_summary->'action_id') = 'string' AND length(state_summary->>'action_id') BETWEEN 1 AND 128))
        WHEN 'action' THEN state_summary - ARRAY['type','state','resolution'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('accepted','queued','pending_approval','ready_to_dispatch','may_have_executed','succeeded','failed_known','cancelled_before_dispatch','cancelled_confirmed','outcome_unknown')
            AND (state_summary->>'resolution' IS NULL OR (state_summary->>'state' = 'outcome_unknown' AND state_summary->>'resolution' IN ('confirmed_executed','confirmed_not_executed','abandoned')))
        WHEN 'approval_required' THEN state_summary - ARRAY['type','approval_id'] = '{}'::jsonb
            AND aggregate_revision > 0 AND jsonb_typeof(state_summary->'approval_id') = 'string' AND length(state_summary->>'approval_id') BETWEEN 1 AND 128
        WHEN 'approval' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('approved','denied','expired')
        WHEN 'control' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('agent','human')
        WHEN 'download' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' = 'completed'
        WHEN 'artifact' THEN state_summary - ARRAY['type','state'] = '{}'::jsonb
            AND aggregate_revision > 0 AND state_summary->>'state' IN ('uploading','stored','scanning','available','quarantined','rejected','generating','finalizing','failed','deleting','deleted')
        ELSE FALSE
    END) IS TRUE
);
