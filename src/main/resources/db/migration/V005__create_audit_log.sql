CREATE TABLE audit_log (
    id          UUID PRIMARY KEY,
    entity_type VARCHAR(50)  NOT NULL,
    entity_id   UUID         NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    actor_id    UUID,
    metadata    TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_entity ON audit_log (entity_type, entity_id);
