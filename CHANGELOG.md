# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
