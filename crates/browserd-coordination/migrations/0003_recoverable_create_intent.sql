ALTER TABLE browserd_create_session_operations
    ADD COLUMN canonical_request JSONB,
    ADD COLUMN downstream_dedupe_key BYTEA,
    ADD COLUMN accepted_at TIMESTAMPTZ,
    ADD COLUMN admission_deadline TIMESTAMPTZ,
    ADD COLUMN policy_context JSONB,
    ADD COLUMN dispatch_generation BIGINT NOT NULL DEFAULT 0 CHECK (dispatch_generation >= 0),
    ADD CONSTRAINT browserd_downstream_dedupe_key_size CHECK (octet_length(downstream_dedupe_key) = 32),
    ADD CONSTRAINT browserd_create_intent_objects CHECK (
        jsonb_typeof(canonical_request) = 'object'
        AND jsonb_typeof(policy_context) = 'object'
        AND admission_deadline > accepted_at
    );

UPDATE browserd_create_session_operations SET
    canonical_request = '{}',
    downstream_dedupe_key = decode(md5(operation_id::text) || md5('browserd:' || operation_id::text), 'hex'),
    accepted_at = created_at,
    admission_deadline = created_at + interval '30 seconds',
    policy_context = '{}';

ALTER TABLE browserd_create_session_operations
    ALTER COLUMN canonical_request SET NOT NULL,
    ALTER COLUMN downstream_dedupe_key SET NOT NULL,
    ALTER COLUMN accepted_at SET NOT NULL,
    ALTER COLUMN admission_deadline SET NOT NULL,
    ALTER COLUMN policy_context SET NOT NULL;

ALTER TABLE browserd_create_session_operations
    ADD CONSTRAINT browserd_dispatch_lease_state CHECK (
        (state = 'creating') =
        (dispatch_lease_token IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL)
    );
