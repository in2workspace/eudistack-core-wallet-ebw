# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] - 2026-04-23

### Fixed

- **EBW local startup**: removed obsolete `FlywayConfig` (in `com.eudistack.ebw.infrastructure.configuration`) that declared a manual `Flyway` bean bypassing `spring.flyway.enabled: false`. Its `dataSource(url, user, password)` call used `FlywayProperties` where only `url` was injected, causing SCRAM-auth failure at boot. `TenantSchemaFlywayMigrator` is the single migration path for `public` + tenant schemas.

### Changed

- **OTLP configuration aligned with Verifier/Issuer**: added `management.otlp.tracing.endpoint` and `management.otlp.metrics.export.enabled: false` to `application.yaml`. EBW was sending OTLP metrics to Jaeger's `/v1/metrics` (404) because no explicit tracing endpoint was configured. Traces now go to `${OTEL_EXPORTER_OTLP_ENDPOINT}/v1/traces`; metrics remain exposed via `/prometheus`.

## [1.1.1] - 2026-04-23

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
