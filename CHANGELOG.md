# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
