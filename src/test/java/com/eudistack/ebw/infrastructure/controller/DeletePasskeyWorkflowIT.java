package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.spi.TokenSigner;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@link com.eudistack.ebw.application.workflow.DeletePasskeyWorkflow},
 * exercised through the {@code DELETE /api/v1/auth/passkeys/{id}} HTTP surface with the same
 * self-contained Testcontainers + per-tenant-schema Flyway setup as {@link PasskeyControllerIT}.
 * This deliberately avoids extending {@code IntegrationTestBase}, whose fallback ("system"
 * tenant, schema {@code public}) does not carry the business tables — see the EUD-103
 * backend-test-blocker note in project memory. This class provisions its own real tenant
 * schema instead, exactly like {@link PasskeyControllerIT} (confirmed green independently
 * of that gap).
 *
 * <p>Where {@link PasskeyControllerIT} asserts the HTTP contract (status codes), this class
 * asserts the side effects {@code DeletePasskeyWorkflow} guarantees at the database level:
 * <ul>
 *   <li>AC-04 — refresh tokens tied to the deleted passkey are revoked ({@code revoked = true}),
 *       and only those — tokens tied to a different passkey are left untouched</li>
 *   <li>AC-03 — the deleted passkey row is gone from {@code user_passkey}</li>
 *   <li>AC-07 — a {@code PASSKEY_DELETED} row is written to {@code audit_log}</li>
 * </ul>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class DeletePasskeyWorkflowIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT = "pskwfit";
    private static final String SCHEMA = TENANT + SCHEMA_SUFFIX;
    private static final String HOST_HEADER = TENANT + ".eudistack.net";
    private static final String VALID_TOKEN = "valid-bearer-token";
    private static final UUID USER_A = UUID.fromString("cccccccc-0000-0000-0000-000000000003");

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("passkey_wf_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/passkey_wf_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/passkey_wf_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean
    TokenSigner tokenSigner;

    @Autowired
    WebTestClient webClient;

    @BeforeAll
    static void provisionSchema() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA);
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(SCHEMA)
                .schemas(SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void setUp() throws SQLException {
        cleanTables();
        when(tokenSigner.verify(VALID_TOKEN)).thenReturn(
                Map.of("sub", USER_A.toString(), "email", "user-a@test.com"));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void cleanTables() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute("DELETE FROM " + SCHEMA + ".audit_log");
            conn.createStatement().execute("DELETE FROM " + SCHEMA + ".refresh_token");
            conn.createStatement().execute("DELETE FROM " + SCHEMA + ".user_passkey");
            conn.createStatement().execute("DELETE FROM " + SCHEMA + ".wallet_user");
        }
    }

    private void seedUser(UUID userId, String email) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + SCHEMA + ".wallet_user (id, email) VALUES ('"
                    + userId + "', '" + email + "') ON CONFLICT (id) DO NOTHING");
        }
    }

    private void seedPasskey(UUID id, UUID userId, String credentialId, String displayName) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + SCHEMA + ".user_passkey "
                    + "(id, user_id, credential_id, display_name, user_agent, created_at) VALUES ('"
                    + id + "', '" + userId + "', '" + credentialId + "', '" + displayName
                    + "', 'test-agent', NOW())");
        }
    }

    private void seedRefreshToken(UUID id, UUID userId, UUID passkeyId, String tokenHash) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + SCHEMA + ".refresh_token "
                    + "(id, user_id, passkey_id, token_hash, expires_at, revoked) VALUES ('"
                    + id + "', '" + userId + "', '" + passkeyId + "', '" + tokenHash
                    + "', NOW() + INTERVAL '30 days', FALSE)");
        }
    }

    /** Looked up by the token's own id, not passkey_id: the FK is ON DELETE SET NULL, so
     *  passkey_id on this row is nulled out by Postgres once the passkey row is deleted. */
    private boolean isRefreshTokenRevoked(UUID id) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT revoked FROM " + SCHEMA + ".refresh_token WHERE id = '" + id + "'")) {
            assertThat(rs.next()).as("refresh_token row must still exist").isTrue();
            return rs.getBoolean("revoked");
        }
    }

    private boolean passkeyExists(UUID id) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT 1 FROM " + SCHEMA + ".user_passkey WHERE id = '" + id + "'")) {
            return rs.next();
        }
    }

    private int countAuditLogEntries(UUID entityId, String action, UUID actorId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + SCHEMA + ".audit_log "
                     + "WHERE entity_type = 'passkey' AND entity_id = '" + entityId + "' "
                     + "AND action = '" + action + "' AND actor_id = '" + actorId + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private void deleteTarget(UUID id) {
        webClient.delete().uri("/api/v1/auth/passkeys/{id}", id)
                .header("Host", HOST_HEADER)
                .header("Authorization", "Bearer " + VALID_TOKEN)
                .exchange()
                .expectStatus().isNoContent();
    }

    // -------------------------------------------------------------------------
    // AC-04 — refresh tokens tied to the deleted passkey are revoked
    // -------------------------------------------------------------------------

    @Test
    void deletePasskey_revokesRefreshTokenTiedToIt() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-remaining", "Laptop");
        UUID tokenId = UUID.randomUUID();
        seedRefreshToken(tokenId, USER_A, target, "hash-1");

        deleteTarget(target);

        assertThat(isRefreshTokenRevoked(tokenId)).isTrue();
    }

    @Test
    void deletePasskey_revokesAllRefreshTokensWhenMultipleExistForTheSamePasskey() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-remaining", "Laptop");
        UUID tokenId1 = UUID.randomUUID();
        UUID tokenId2 = UUID.randomUUID();
        seedRefreshToken(tokenId1, USER_A, target, "hash-1");
        seedRefreshToken(tokenId2, USER_A, target, "hash-2");

        deleteTarget(target);

        assertThat(isRefreshTokenRevoked(tokenId1)).isTrue();
        assertThat(isRefreshTokenRevoked(tokenId2)).isTrue();
    }

    @Test
    void deletePasskey_doesNotRevokeRefreshTokensOfAnotherPasskey() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        UUID remaining = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone");
        seedPasskey(remaining, USER_A, "cred-remaining", "Laptop");
        UUID untouchedTokenId = UUID.randomUUID();
        seedRefreshToken(untouchedTokenId, USER_A, remaining, "hash-remaining");

        deleteTarget(target);

        assertThat(isRefreshTokenRevoked(untouchedTokenId)).isFalse();
    }

    // -------------------------------------------------------------------------
    // AC-03 — the deleted passkey row is gone from user_passkey
    // -------------------------------------------------------------------------

    @Test
    void deletePasskey_removesTheRowFromUserPasskey() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-remaining", "Laptop");

        deleteTarget(target);

        assertThat(passkeyExists(target)).isFalse();
    }

    // -------------------------------------------------------------------------
    // AC-07 — a PASSKEY_DELETED audit event is emitted
    // -------------------------------------------------------------------------

    @Test
    void deletePasskey_emitsPasskeyDeletedAuditEvent() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-remaining", "Laptop");

        deleteTarget(target);

        assertThat(countAuditLogEntries(target, "PASSKEY_DELETED", USER_A)).isEqualTo(1);
    }
}
