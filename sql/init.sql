-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
-- SPDX-License-Identifier: Apache-2.0

-- Bill8:Webhooks - the service's own schema `webhooks`: endpoints,
-- materialized events, deliveries. Signing secrets are secret-by-reference.

CREATE SCHEMA IF NOT EXISTS webhooks;

CREATE TABLE IF NOT EXISTS webhooks.webhook_endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    url             TEXT NOT NULL,
    enabled_events  JSONB NOT NULL DEFAULT '[]',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    secret_ref      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_webhooks_endpoints_env ON webhooks.webhook_endpoints (env_id);

CREATE TABLE IF NOT EXISTS webhooks.events (
    id          UUID PRIMARY KEY,
    env_id      UUID NOT NULL,
    event_type  TEXT NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_events_env ON webhooks.events (env_id);

CREATE TABLE IF NOT EXISTS webhooks.deliveries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    event_id            UUID NOT NULL REFERENCES webhooks.events(id),
    endpoint_id         UUID NOT NULL REFERENCES webhooks.webhook_endpoints(id),
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'succeeded', 'retry', 'dead')),
    attempts            INTEGER NOT NULL DEFAULT 0,
    last_attempted_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_deliveries_env ON webhooks.deliveries (env_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_deliveries_retry ON webhooks.deliveries (last_attempted_at) WHERE status = 'retry';

-- ── Row-level security ────────────────────────────────────────────────
ALTER TABLE webhooks.webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks.webhook_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE webhooks.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks.events FORCE ROW LEVEL SECURITY;
ALTER TABLE webhooks.deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks.deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON webhooks.webhook_endpoints USING (env_id = current_setting('app.env_id', true)::uuid);
CREATE POLICY tenant_isolation ON webhooks.events USING (env_id = current_setting('app.env_id', true)::uuid);
CREATE POLICY tenant_isolation ON webhooks.deliveries USING (env_id = current_setting('app.env_id', true)::uuid);

-- ── Producer tables ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks.outbox (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    event_type          TEXT NOT NULL,
    stream_family       TEXT NOT NULL,
    payload             JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed             BOOLEAN NOT NULL DEFAULT false,
    relayed_at          TIMESTAMPTZ,
    relay_attempts      INT NOT NULL DEFAULT 0,
    next_retry_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_outbox_unrelayed ON webhooks.outbox (created_at) WHERE relayed = false;

CREATE OR REPLACE FUNCTION webhooks.notify_outbox_changed() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('webhooks_outbox_changed', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS webhooks_outbox_notify ON webhooks.outbox;
CREATE TRIGGER webhooks_outbox_notify AFTER INSERT ON webhooks.outbox
    FOR EACH ROW EXECUTE FUNCTION webhooks.notify_outbox_changed();

CREATE TABLE IF NOT EXISTS webhooks.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_audit_journal_unpushed
    ON webhooks.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE webhooks.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON webhooks.audit_journal;
CREATE POLICY audit_journal_dml ON webhooks.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
-- ── Role grants (schema-ownership convention, bank8-ledger's form) ─────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bill8_webhooks_service') THEN
        ALTER ROLE bill8_webhooks_service SET search_path = webhooks, public;
        GRANT USAGE ON SCHEMA webhooks TO bill8_webhooks_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA webhooks TO bill8_webhooks_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA webhooks TO bill8_webhooks_service;
    END IF;
END $$;
