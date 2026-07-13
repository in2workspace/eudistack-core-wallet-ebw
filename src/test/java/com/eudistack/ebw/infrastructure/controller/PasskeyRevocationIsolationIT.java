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
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration tests proving account- and tenant-level isolation for
 * {@code DELETE /api/v1/auth/passkeys/{id}} (EUD-144).
 *
 * <p>Same self-contained Testcontainers + two-tenant-schema Flyway setup as
 * {@link PasskeyIsolationIT} (EUD-143's GET isolation suite) — deliberately does not
 * extend {@code IntegrationTestBase}, avoiding the multi-tenant migration gap tracked
 * in project memory as the EUD-103 backend-test-blocker.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-05 — a holder of account A can never delete a passkey belonging to account B,
 *   whether B is in the same tenant or a different one, even when both accounts happen
 *   to share the same {@code userId} value (proves isolation comes from the schema-per-tenant
 *   boundary and the {@code findByIdAndUserId} ownership check, not from userId equality
 *   alone).</li>
 *   <li>ES-02 — the response for "passkey doesn't exist" and "passkey belongs to someone
 *   else" is byte-for-byte indistinguishable (anti-enumeration): both resolve through the
 *   same {@code findByIdAndUserId} empty-result path and the same fixed
 *   {@code PasskeyNotFoundException} message.</li>
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
class PasskeyRevocationIsolationIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT_1 = "pskrevisoa";
    private static final String TENANT_2 = "pskrevisob";
    private static final String SCHEMA_1 = TENANT_1 + SCHEMA_SUFFIX;
    private static final String SCHEMA_2 = TENANT_2 + SCHEMA_SUFFIX;
    private static final String HOST_1 = TENANT_1 + ".eudistack.net";
    private static final String HOST_2 = TENANT_2 + ".eudistack.net";

    private static final String TOKEN_USER_A = "token-user-a";
    private static final String TOKEN_USER_B = "token-user-b";

    // Same UUID reused across two tenant schemas on purpose — proves isolation
    // comes from the schema-per-tenant boundary, not merely from userId equality.
    private static final UUID USER_A = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID USER_B = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("passkey_revocation_isolation_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/passkey_revocation_isolation_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/passkey_revocation_isolation_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean
    TokenSigner tokenSigner;

    @Autowired
    WebTestClient webClient;

    @BeforeAll
    static void provisionSchemas() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA_1);
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + SCHEMA_2);
        }
        runTenantMigrations(jdbcUrl, SCHEMA_1);
        runTenantMigrations(jdbcUrl, SCHEMA_2);
    }

    private static void runTenantMigrations(String jdbcUrl, String schema) {
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void setUp() throws SQLException {
        cleanTables(SCHEMA_1);
        cleanTables(SCHEMA_2);
        when(tokenSigner.verify(TOKEN_USER_A)).thenReturn(
                Map.of("sub", USER_A.toString(), "email", "user-a@test.com"));
        when(tokenSigner.verify(TOKEN_USER_B)).thenReturn(
                Map.of("sub", USER_B.toString(), "email", "user-b@test.com"));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void cleanTables(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute("DELETE FROM " + schema + ".refresh_token");
            conn.createStatement().execute("DELETE FROM " + schema + ".user_passkey");
            conn.createStatement().execute("DELETE FROM " + schema + ".wallet_user");
        }
    }

    private void seedUser(String schema, UUID userId, String email) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".wallet_user (id, email) VALUES ('"
                    + userId + "', '" + email + "') ON CONFLICT (id) DO NOTHING");
        }
    }

    private void seedPasskey(String schema, UUID id, UUID userId, String credentialId, String displayName)
            throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".user_passkey "
                    + "(id, user_id, credential_id, display_name, user_agent, created_at, last_used_at) VALUES ('"
                    + id + "', '" + userId + "', '" + credentialId + "', '"
                    + displayName.replace("'", "''")
                    + "', 'test-agent', '2026-01-01T10:00:00Z', NULL)");
        }
    }

    private boolean passkeyExists(String schema, UUID id) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             var rs = conn.createStatement().executeQuery(
                     "SELECT 1 FROM " + schema + ".user_passkey WHERE id = '" + id + "'")) {
            return rs.next();
        }
    }

    private WebTestClient.ResponseSpec deleteWithAuth(String host, UUID id, String bearer) {
        return webClient.delete()
                .uri("/api/v1/auth/passkeys/{id}", id)
                .header("Host", host)
                .header("Authorization", "Bearer " + bearer)
                .exchange();
    }

    // -------------------------------------------------------------------------
    // AC-05 — same tenant, two accounts: A cannot delete B's passkey
    // -------------------------------------------------------------------------

    @Test
    void delete_sameTenantTwoAccounts_accountACannotDeleteAccountBsPasskey() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedPasskey(SCHEMA_1, UUID.randomUUID(), USER_A, "cred-a-1", "A's iPhone");
        UUID bsPasskey = UUID.randomUUID();
        seedPasskey(SCHEMA_1, bsPasskey, USER_B, "cred-b-1", "B's Pixel");

        deleteWithAuth(HOST_1, bsPasskey, TOKEN_USER_A)
                .expectStatus().isNotFound();

        assertThat(passkeyExists(SCHEMA_1, bsPasskey))
                .as("A's failed attempt must not delete B's passkey")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // AC-05 — different tenants, same userId: no cross-tenant deletion
    // -------------------------------------------------------------------------

    @Test
    void delete_differentTenantsSameUserId_cannotDeleteAcrossTenantBoundary() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@tenant1.com");
        seedUser(SCHEMA_2, USER_A, "user-a@tenant2.com");
        seedPasskey(SCHEMA_1, UUID.randomUUID(), USER_A, "cred-tenant1", "Tenant 1 Device");
        UUID tenant2Passkey = UUID.randomUUID();
        seedPasskey(SCHEMA_2, tenant2Passkey, USER_A, "cred-tenant2", "Tenant 2 Device");

        // Same userId, but the request is scoped to tenant 1 (Host header) — the passkey
        // only exists in tenant 2's schema, so it must be unreachable from tenant 1.
        deleteWithAuth(HOST_1, tenant2Passkey, TOKEN_USER_A)
                .expectStatus().isNotFound();

        assertThat(passkeyExists(SCHEMA_2, tenant2Passkey))
                .as("a cross-tenant delete attempt must not reach the other tenant's schema")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // ES-02 — anti-enumeration: nonexistent id and not-owned id are indistinguishable
    // -------------------------------------------------------------------------

    @Test
    void delete_nonExistentAndNotOwnedPasskey_returnIndistinguishableResponses() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedPasskey(SCHEMA_1, UUID.randomUUID(), USER_A, "cred-a-1", "A's iPhone");
        UUID bsPasskey = UUID.randomUUID();
        seedPasskey(SCHEMA_1, bsPasskey, USER_B, "cred-b-1", "B's Pixel");

        Map<String, Object> notFoundBody = deleteWithAuth(HOST_1, UUID.randomUUID(), TOKEN_USER_A)
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult()
                .getResponseBody();

        Map<String, Object> notOwnedBody = deleteWithAuth(HOST_1, bsPasskey, TOKEN_USER_A)
                .expectStatus().isNotFound()
                .expectBody(Map.class)
                .returnResult()
                .getResponseBody();

        // "instance" is excluded on purpose: WebFlux auto-populates it from the request path,
        // so it trivially echoes back whichever id the caller put in the URL — that's not
        // server-derived information and isn't what anti-enumeration is about. The fields that
        // could actually leak whether the passkey exists (type/title/status/detail) must match.
        assertThat(notFoundBody.get("type"))
                .as("'doesn't exist' and 'not yours' must be indistinguishable to the caller")
                .isEqualTo(notOwnedBody.get("type"));
        assertThat(notFoundBody.get("title")).isEqualTo(notOwnedBody.get("title"));
        assertThat(notFoundBody.get("status")).isEqualTo(notOwnedBody.get("status"));
        assertThat(notFoundBody.get("detail")).isEqualTo(notOwnedBody.get("detail"));
    }
}
