# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Health endpoint normalized to `/health`** — Added `base-path: /` and `path-mapping` so health responds at `/health` instead of `/actuator/health`. Added liveness/readiness probes, Spring Boot 3.5 `access` API, and parameterized `show-details` via env var.

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
