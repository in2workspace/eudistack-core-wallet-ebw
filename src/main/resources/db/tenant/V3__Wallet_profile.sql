-- =============================================================================
-- V3__Wallet_profile.sql
-- Per-tenant wallet profile table: stores wallet_mode and key_manager
-- configuration that drives discovery (EUDISTACK-412 / US-01).
--
-- Architecture ref: docs/EUDISTACK-411-per-tenant-wallet-mode-and-key-manager-config/specs/architecture.md §8.2
-- ADR: AD-412-1 (PK on tenant string), AD-412-4 (conditional GRANT via DO block)
-- AC coverage: AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, EC-01, EC-02, EC-03, EC-04, ES-01, ES-03
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: tenant_wallet_profile
--
-- One row per tenant, keyed by the stable tenant identifier string (AD-412-1).
-- The CHECK constraint chk_wallet_profile_mode_manager is the PRIMARY enforcement
-- of the FR-10/FR-11 invariant at the persistence layer:
--   - browser mode MUST have key_manager = NULL
--   - server mode MUST have key_manager IN ('db','hybrid','hsm','qtsp')
--
-- The Java domain record TenantWalletProfile enforces the same invariant in its
-- compact constructor as defense-in-depth (AD-412-2); both must remain coherent.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_wallet_profile (
    tenant       VARCHAR(255) NOT NULL,
    wallet_mode  VARCHAR(20)  NOT NULL,
    key_manager  VARCHAR(20),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT pk_tenant_wallet_profile
        PRIMARY KEY (tenant),

    CONSTRAINT chk_wallet_profile_mode_manager CHECK (
        (wallet_mode = 'browser' AND key_manager IS NULL)
        OR
        (wallet_mode = 'server' AND key_manager IS NOT NULL
            AND key_manager IN ('db', 'hybrid', 'hsm', 'qtsp'))
    )
);

-- -----------------------------------------------------------------------------
-- ACL: Revoke default public access, then grant least-privilege per role matrix.
--
-- ebw_app_role   : SELECT only — the EBW application runtime reads the profile
--                  to drive discovery (AC-06, EC-05). Write access would violate
--                  the operator-only mutation contract (architecture.md AD-2).
--
-- config_manager_role : SELECT/INSERT/UPDATE — the configuration manager actor
--                       provisions and updates tenant profiles (AC-06).
--                       DELETE is intentionally omitted: a tenant that is
--                       deactivated is flagged, never deleted (architecture.md AD-2
--                       Consequences). This is enforced by the absence of GRANT.
--
-- The GRANT to config_manager_role is wrapped in a DO block (AD-412-4) so that
-- this migration runs cleanly in dev-local environments where the role has not
-- been provisioned yet (IaC + US-09 runbook are responsible for that role in
-- STG/PROD). In CI, TestContainers creates the role explicitly before applying
-- the migration, ensuring full ACL coverage is exercised (WalletProfileRoleAclIT).
-- -----------------------------------------------------------------------------
REVOKE ALL ON tenant_wallet_profile FROM PUBLIC;

GRANT SELECT ON tenant_wallet_profile TO ebw_app_role;

DO $$
BEGIN
    GRANT SELECT, INSERT, UPDATE ON tenant_wallet_profile TO config_manager_role;
EXCEPTION
    WHEN undefined_object THEN
        NULL; -- config_manager_role not provisioned in this environment (dev-local); skip silently
END
$$;