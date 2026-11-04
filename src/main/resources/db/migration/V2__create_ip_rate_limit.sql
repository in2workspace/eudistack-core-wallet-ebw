-- =============================================================================
-- V2__create_ip_rate_limit.sql
-- Per-IP request counters shared by every EBW task (EUD-310). One row per
-- rate key ("<budget>:ip:<address>"); the window starts with the first request
-- and the counter restarts once expires_at has passed.
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.ip_rate_limit (
    rate_key   VARCHAR(255) PRIMARY KEY,
    hits       INTEGER      NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_rate_limit_expires_at ON public.ip_rate_limit (expires_at);
