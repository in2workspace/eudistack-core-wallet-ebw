# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **EUDISTACK-413 — V3 migration: `chk_twc_server_requires_key_manager` CHECK constraint.** New forward migration `db/migration/V3__Server_requires_key_manager.sql` adds `ALTER TABLE public.tenant_wallet_config ADD CONSTRAINT chk_twc_server_requires_key_manager CHECK (NOT (wallet_mode = 'server' AND key_manager IS NULL))` — the counterpart of the `chk_twc_browser_no_key_manager` CHECK from V2 (EUDISTACK-412). Together they enforce the full wallet_mode/key_manager pairing invariant (`browser ⇒ key_manager IS NULL`, `server ⇒ key_manager IS NOT NULL`). This is the **primary enforcer of FR-21** in EUDISTACK-411: a seed SQL that attempts `wallet_mode='server'` with `key_manager=NULL` is rejected by PostgreSQL before any row is written. The migration is additive-safe (it is compatible with the pre-existing DOME `server`+`db-tde` row seeded in EUDISTACK-412 commit `ab2baa0`) and backward-compatible (no API change). Applied by `TenantSchemaFlywayMigrator#migratePublicSchema` on EBW startup. Reversible: `DROP CONSTRAINT IF EXISTS chk_twc_server_requires_key_manager`. Note: `db/tenant/V3__Wallet_config_audit.sql` is a different Flyway migration location (`db/tenant/`) and does not collide. Pre-deployment pre-check documented in the runbook. Implements EUDISTACK-411 US-02 (AC-2).
- **EUDISTACK-413 — Test coverage for the `server`+`db-tde` case.** Extended `WalletTenantConfigReadServiceTest` with two new server cases: `retrieveDescriptor_serverDbTdeTenantExists_returnsDescriptorWithKeyManagerPresent` and `retrieveDescriptor_serverTenant_forwardsNormalisedHostToPortUnchanged`. New `WalletTenantConfigMapperTest` (infrastructure layer): asserts a `WalletTenantConfigEntity{walletMode='server', keyManager='db-tde'}` maps to a descriptor with `walletMode=SERVER`, `keyManager=Optional.of(DB_TDE)`, `naturalPersonsOnly=false`, `supportedCredentials=[]`; and that `DiscoveryResponseDto.from(server descriptor)` omits `key_manager` (AD-1bis — no `keyManager()` accessor on the DTO record). Extended `TenantWalletConfigSchemaMigrationIT` (Testcontainers) with six new V3 cases: server+NULL rejected by `chk_twc_server_requires_key_manager`; server+db-tde accepted; ON CONFLICT DO NOTHING idempotent; V3 migration additive-safe over pre-existing DOME row; constraint visible in `pg_constraint`; read adapter resolves server+db-tde row to `walletMode=SERVER`/`keyManager=DB_TDE`. Extended `WalletTenantConfigDiscoveryControllerIT` with five new server cases: 200 with 4-field projection + explicit absence assertion for `key_manager`/`activation_status` (AC-1b, AC-1d, AD-1bis); uppercase Host → 200 (AC-1e); Host with port → 200 (AC-1e); unregistered server host → 404 opaque not cached (AC-5a, AC-5b). `WalletConfigArchitectureTest` (ArchUnit) passes unchanged — the read path is mode-agnostic; no new rules needed. Port-stripping added to the controller host normalisation (lowercase + strip `:port` suffix — AC-1e; CloudFront strips ports in production, but direct/test callers may include one). Implements EUDISTACK-411 US-02 (AC-1, AC-2, AC-5).
- **EUDISTACK-413 — Runbook extended with `server`+`db-tde` seed procedure.** `docs/EUDISTACK-411-wallet-tenant-configuration/runbooks/register-browser-tenant.md` (renamed scope: covers all discovery-plane tenants) extended with a `server`+`db-tde` section: column values (`wallet_mode='server'`, `key_manager` NOT NULL), note on `chk_twc_server_requires_key_manager`, pre-deployment pre-check (`SELECT count(*) WHERE wallet_mode='server' AND key_manager IS NULL` → must be 0), verification `curl` with DOME host expecting `wallet_mode="server"` without `key_manager`, and server-specific troubleshooting entries. Seed comments in `seed-tenants.sql` and `seed-tenants.stg.sql` updated to reference the V3 CHECK constraints and the V3 migration. Implements EUDISTACK-411 US-02 (AC-3).

  > **Note — out-of-scope (→ other Stories):** The on-write rejection `server ⇒ key_manager defined` with a human-readable message + audit-on-write belongs to **EUDISTACK-55** (Config Management). The operational plane for `db-tde` (`wallet_operational_config`) belongs to **EUDISTACK-414** (US-03). The EBW's runtime consumption of `key_manager` to activate `db-tde` persistence is not part of EUDISTACK-411.

- **EUDISTACK-412 — Wallet tenant discovery plane (read-only).** New public, session-less endpoint `GET /business-wallet/.well-known/wallet-config-metadata` that resolves the requesting tenant from the `Host` header and returns the 4-field projection `{wallet_mode, natural_persons_only, supported_credentials, version}` — `key_manager` is deliberately never exposed (AD-1bis). The response is cacheable on CloudFront with a 60-second TTL and an `ETag: "<version>"` (`Cache-Control: public, max-age=60`, `Vary: Host`); an unregistered host gets an opaque `404` (RFC 9457, `about:blank`, same timing as the `200`); a missing/blank `Host` header gets `400` (`urn:eudistack:error:missing-host-header`). EUDIW browser wallets can read their tenant mode from this plane instead of the build-time `WALLET_MODE` env var (build-time fallback on failure — the EUDIW consumer side is delivered by EUDISTACK-37). New `wallet.config` bounded context (hexagonal, read-only): `WalletMode` / `KeyManager` (kebab-case values) / `TenantWalletConfigDescriptor`; `WalletTenantConfigReadService`; `TenantConfigurationPort.findByHost`; an R2DBC read adapter that queries `public.tenant_wallet_config` exclusively through a `search_path=public` connection (`PublicSchemaConnectionFactory`) so the discovery path never touches a tenant schema (AD-1, enforced by ArchUnit). Discovery-plane data is seeded manually via SQL (`eudistack-platform-dev/postgres/seed-tenants.sql`; procedure documented in `docs/EUDISTACK-411-wallet-tenant-configuration/runbooks/register-browser-tenant.md`); the discovery-plane **write** side (admin write API, single model writer, on-write pairing validations, change audit, targeted CloudFront invalidation) is delivered by **EUDISTACK-55** (Config Management). `eudistack-platform-iac` contributes the CloudFront cache policy + the `/.well-known/wallet-config-metadata*` ordered behavior + a viewer-request CloudFront function that rewrites the path to the `/business-wallet` base-path. Implements EUDISTACK-411 US-01 (read side).
- **EUDISTACK-412 — Flyway migrations for the wallet discovery plane.** `db/migration/V2__Create_tenant_wallet_config.sql` creates `public.tenant_wallet_config` (`schema_name` PK + FK→`public.tenant_registry`, `host` NOT NULL UNIQUE + index, `wallet_mode`, `key_manager` nullable, `natural_persons_only`, `version`, `updated_by`/`updated_at`/`created_at`) with CHECK constraints `wallet_mode IN ('browser','server')`, `key_manager IS NULL OR key_manager IN ('db-tde','hybrid','hsm','qtsp')` (kebab-case), and `NOT (wallet_mode='browser' AND key_manager IS NOT NULL)` (FR-20) — these CHECK constraints are the primary enforcer of the wallet_mode/key_manager pairing rules (there is no on-write validation in the EBW; that belongs to EUDISTACK-55). `db/tenant/V3__Wallet_config_audit.sql` creates `<tenant>_business_wallet.wallet_config_audit` plus a `BEFORE UPDATE OR DELETE` append-only trigger — the table only; it is written by EUDISTACK-55, not by anything in EUDISTACK-411. (These tables belong with the EBW, which owns and migrates the `public` schema via `TenantSchemaFlywayMigrator`, as `tenant_wallet_config` is a sibling of `tenant_registry` — feature-design §4.2.)

## [1.1.7] - 2026-04-24

### Changed

- **`spring.webflux.base-path`: `/wallet` → `/business-wallet`**: align backend base-path with the public URL published by the ALB (`https://<tenant>-stg.eudistack.net/business-wallet/...`). IaC already routed both `/wallet/*` and `/business-wallet/*` to the service but only `/business-wallet/*` is public. All endpoints (auth, actuator) move accordingly. Tracked in EUDISTACK-168.

## [1.1.6] - 2026-04-24

### Fixed

- **Aggregate `/wallet/health` returned 503 on STG**: even after 1.1.5 fixed the 401, the ALB probe kept failing because Spring's default `MailHealthIndicator` was DOWN. Applied the same fix shipped in `eudistack-core-issuer` 3.4.4: (1) replaced the default indicator with a custom `SmtpHealthIndicator` that selects the `smtps` transport when SSL is enabled or port is 465 (implicit TLS) — the default always uses plain `smtp` and hangs on AWS SES `:465`; (2) disabled `management.health.mail.enabled` so the two indicators don't overlap; (3) defined `management.endpoint.health.group.readiness`/`liveness` including only `readinessState`/`livenessState`, so SMTP remains visible in the aggregate but cannot take the ECS task out of the ALB pool. Tracked in EUDISTACK-168.

## [1.1.5] - 2026-04-24

### Fixed

- **Actuator health returning 401 on AWS**: aligned `SecurityConfig` with Issuer/Verifier Core by permitting both `/health` and `/health/**` pathMatchers. With `spring.webflux.base-path=/wallet`, Spring Security sees the path without the base-path prefix, but `pathMatchers("/health/**")` alone does not match the bare `/health` path in Spring 6 — only subpaths (`/health/liveness`, `/health/readiness`). This caused ALB target-group health checks to `/wallet/health` to return 401 Unauthorized. Also aligned the local Docker Compose healthcheck to probe `/wallet/health` (previously `/health`, which 404'd due to the WebFlux base-path). Tracked in EUDISTACK-168.

## [1.1.4] - 2026-04-23

### Fixed

- **CI deploy health check — command substitution under `set -e`**: 1.1.3 downgraded the step to warning-only, but the curl itself still exited with code 6 (DNS failure) inside `$(...)`, which tripped `set -euo pipefail` and failed the job before the `if` branch ran. Appended `|| echo "000"` so the command substitution always returns a value and the warning branch can execute. Same pattern as the verifier workflow. Tracked in EUDISTACK-168.

## [1.1.3] - 2026-04-23

### Changed

- **CI deploy health check is now warning-only**: `deploy.yml` failed the deploy on non-200 responses, but `HEALTH_URL` points to `business-wallet-<env>.api.altia.eudistack.net`, a host that does not resolve from the GitHub runner (`altia` subdomain not published in Route53). Aligned the step to emit `::warning::` instead of `::error::` + `exit 1`, matching verifier 3.1.3 and issuer. Target-group health checks via `aws ecs wait services-stable` keep validating task health. Tracked in EUDISTACK-168.

## [1.1.2] - 2026-04-23

### Fixed

- **EBW local startup**: removed obsolete `FlywayConfig` (in `com.eudistack.ebw.infrastructure.configuration`) that declared a manual `Flyway` bean bypassing `spring.flyway.enabled: false`. Its `dataSource(url, user, password)` call used `FlywayProperties` where only `url` was injected, causing SCRAM-auth failure at boot. `TenantSchemaFlywayMigrator` is the single migration path for `public` + tenant schemas.

### Changed

- **OTLP configuration aligned with Verifier/Issuer**: added `management.otlp.tracing.endpoint` and `management.otlp.metrics.export.enabled: false` to `application.yaml`. EBW was sending OTLP metrics to Jaeger's `/v1/metrics` (404) because no explicit tracing endpoint was configured. Traces now go to `${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces`; metrics remain exposed via `/prometheus`.

## [1.1.1] - 2026-04-23

### Added

- EUDI-040: Wallet credential CRUD endpoints (`POST/GET/PATCH/DELETE /api/credentials`)
- AES-256-GCM at-rest encryption for `credential_raw` (IV prepended, GCM tag 128, per-encryption IV)
- Status lifecycle management with validated transitions (VALID ↔ SUSPENDED, → REVOKED/EXPIRED terminal)
- Audit trail: `CREATED`, `STATUS_CHANGED`, `DELETED` events with correlatable `entity_hash` (SHA-256)
- Cross-user isolation: identical 404 responses for missing vs other-user credentials (anti-enumeration)

### Fixed

- **EBW startup on STG**: disabled Spring Boot's auto-configured `flywayInitializer` (`spring.flyway.enabled: false`) in `application.yaml`. The auto-config was attempting a JDBC connection without user/password (only `SPRING_FLYWAY_URL` is injected in ECS), causing `SCRAM-based authentication, but no password was provided` and aborting context startup. `TenantSchemaFlywayMigrator` continues to run migrations for `public` + all tenant schemas using R2DBC credentials. Mirrors the fix already shipped in `eudistack-core-issuer` 3.4.2.

## [Pending release]

### Fixed

- **DB config aligned with Issuer schema-per-tenant model (EUDI-063).** `application.yaml` defaults were pointing to a standalone DB `ebw` with schema `ebw`, but EBW is tenant-aware and reads `public.tenant_registry` (populated by Issuer) to migrate per-tenant schemas. Switched `spring.r2dbc.*` and `spring.flyway.*` to the same `SPRING_R2DBC_URL/USERNAME/PASSWORD` + `SPRING_FLYWAY_URL` + `SPRING_FLYWAY_DEFAULT_SCHEMA` overrides used by Issuer; defaults now target DB `eudistack` and schema `public`. Added `baseline-on-migrate: true` so Flyway does not refuse to run on the non-empty DB already initialized by Issuer. This unblocks the STG deployment of `wallet-ebw`, which was failing to find `tenant_registry` with the previous defaults.
- `EudiStackWalletEbwApplicationTests > contextLoads()` was failing in CI because the Spring context tried to connect to Postgres (`localhost:5432`). The custom `TenantSchemaFlywayMigrator` (`ApplicationRunner`) ran on boot regardless of Flyway autoconfig. Gated the migrator with `@ConditionalOnProperty(ebw.tenant-flyway.enabled, matchIfMissing = true)` and added `src/test/resources/application.yml` that disables the migrator plus excludes `FlywayAutoConfiguration` / `R2dbcAutoConfiguration` so the smoke test boots without a database. Integration tests requiring DB will need their own profile + Testcontainers when added.

## [1.1.0] - 2026-04-20

### Changed

- **Health endpoint normalized to `/health`** — Added `base-path: /` and `path-mapping` so health responds at `/health` instead of `/actuator/health`. Added liveness/readiness probes, Spring Boot 3.5 `access` API, and parameterized `show-details` via env var.
- Aligned with SaaS multi-tenant platform release v3.1.0; no backend code changes beyond existing EUDI-063 integration.

## [1.0.0] - 2026-03-24

### Added
- Initial project scaffolding
- Gradle build configuration (Java 25, Spring Boot 3, WebFlux)
- CI/CD workflows (build, snapshot, release)
- Dockerfile for containerized deployment
- Email OTP verification flow (6-digit, bcrypt-hashed, 10 min expiry, max 5 attempts).
- JWT ES256 access tokens (15 min TTL) + UUID v4 opaque refresh tokens (7 days, SHA-256 hashed).
- Refresh token rotation with family compromise detection (revoke all on reuse).
- Global logout with audit logging (revokes all user tokens).
- Passkey metadata CRUD (register, list, update, delete, revoke-sessions).
- Per-IP rate limiting via Caffeine cache (WebFilter).
- Per-email rate limiting via domain SPI + Caffeine adapter (workflow-level).
- Payload size limit filter (64 KB).
- Security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy).
- Hexagonal architecture: domain, application, infrastructure layers.
- Flyway migrations V001-V005 (wallet_user, email_verification, user_passkey, refresh_token, audit_log).
- Integration tests with Testcontainers PostgreSQL (20 tests).
- Unit tests for domain services (16 tests).
