CREATE TABLE IF NOT EXISTS policy_changes (
    epoch       BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    change_type TEXT        NOT NULL,
    payload     JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_changes_tenant_epoch
    ON policy_changes (tenant_id, epoch);

CREATE TABLE IF NOT EXISTS zen_nodes (
    zen_id          TEXT PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    applied_epoch   BIGINT      NOT NULL DEFAULT 0,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    region          TEXT        NOT NULL
);
