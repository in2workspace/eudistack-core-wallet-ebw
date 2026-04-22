# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- EUDI-040: Wallet credential CRUD endpoints (`POST/GET/PATCH/DELETE /api/credentials`)
- AES-256-GCM at-rest encryption for `credential_raw` (IV prepended, GCM tag 128, per-encryption IV)
- Status lifecycle management with validated transitions (VALID ↔ SUSPENDED, → REVOKED/EXPIRED terminal)
- Audit trail: `CREATED`, `STATUS_CHANGED`, `DELETED` events with correlatable `entity_hash` (SHA-256)
- Cross-user isolation: identical 404 responses for missing vs other-user credentials (anti-enumeration)

### Fixed

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
