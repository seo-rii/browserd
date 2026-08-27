ALTER TABLE browserd_create_session_operations
    ADD COLUMN dispatch_lease_token UUID,
    ADD COLUMN dispatch_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT browserd_create_session_operations_dispatch_lease_pair CHECK (
        (dispatch_lease_token IS NULL AND dispatch_lease_expires_at IS NULL)
        OR (dispatch_lease_token IS NOT NULL AND dispatch_lease_expires_at IS NOT NULL)
    );
