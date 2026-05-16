# European Business Wallet (EBW) — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo. The
> SDD Constitution lives in `../eudistack-platform-dev/CLAUDE.md`.

## Identity

Java 25 + Spring Boot 3.5 + WebFlux backend of the **European Business
Wallet (EBW)**. Manages organization-level credentials, key custody,
delegation, and signing flows for legal entities. Frontend is
`eudistack-core-wallet-pwa` (Angular + Ionic).

Repo group: `com.eudistack` · current version: see `build.gradle`.

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 3.5.11** + **WebFlux** (reactive)
- **R2DBC** + PostgreSQL (schema-per-tenant)
- **Flyway** for migrations
- **Nimbus JOSE+JWT** + BouncyCastle for crypto
- **WebClient** for outbound HTTP (Issuer, Verifier, QTSP)
- **Testcontainers** for integration tests
- **Checkstyle**, **JaCoCo**, **OWASP dependency-check**

## Architecture (hexagonal)

Same layer rules as Issuer. Reactive stack (Reactor Context for
tenant + security propagation).

Strict rules: `../eudistack-platform-dev/.claude/rules/hexagonal-discipline.md`.

## Multi-tenancy

- Reactive: `TenantContextHolder` via `Mono.deferContextual(ctx -> ...)` + `contextWrite`. Never `ThreadLocal`.
- One PostgreSQL schema per tenant.
- See `../eudistack-platform-dev/.claude/rules/tenant-isolation.md`.

## Key management (specific to EBW)

- Keys stored encrypted in DB; KEK in AWS KMS (per-tenant).
- See `EUDISTACK-5-ebw-key-management/` in platform-dev for the spec.
- Passkey + PRF flows handled in the frontend (Wallet PWA); EBW backend never holds raw key material in plaintext outside the encryption boundary.

## Common commands

> **Dev stack runs in Docker** via `make up` from `eudistack-platform-dev`.

| Task | Command |
|------|---------|
| Compile | `./gradlew compileJava` |
| Unit tests | `./gradlew test` |
| Integration tests | `./gradlew integrationTest` |
| Full check | `./gradlew check` |
| Rebuild Docker image | `cd ../eudistack-platform-dev && make rebuild-ebw-service` |
| Tail logs | `cd ../eudistack-platform-dev && make logs-ebw` |
| OWASP dependency check | `./gradlew dependencyCheckAnalyze` |

## Testing conventions

- `*Test.java` — unit (JUnit 5 + Mockito).
- `*IT.java` — integration (Spring + Testcontainers Postgres).
- WebFlux endpoints: `WebTestClient`.

## Protocols implemented

- **OID4VCI 1.0** — receives credentials from Issuers.
- **OID4VP 1.0** — presents credentials to Verifiers.
- **SD-JWT VC** (RFC 9901).
- **DPoP** (RFC 9449).
- **CSC API v2.0** — QTSP signing flows.

Normative invariants:
`../eudistack-platform-dev/.claude/rules/protocol-compliance.md`.

## Code style

- Lombok where it removes ceremony.
- Constructor injection only.
- Package-by-feature inside hexagonal layers.
- Reactive: every blocking call wrapped in `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())`.

## Where to find specs

`../eudistack-platform-dev/docs/EUDISTACK-NNN-*/EUDISTACK-MMM/`.

## Git workflow

- **Squash merge to `main`.**
- Conventional Commits + Story footer.

## References

- Constitution: [`../eudistack-platform-dev/CLAUDE.md`](../eudistack-platform-dev/CLAUDE.md)
- SAD: [`../eudistack-platform-dev/docs/_shared/architecture/sad.md`](../eudistack-platform-dev/docs/_shared/architecture/sad.md)
- Skills: `java-spring-hexagonal`, `code-review-checklist`, `commit-conventions`
- Rules: `hexagonal-discipline`, `tenant-isolation`, `protocol-compliance`
