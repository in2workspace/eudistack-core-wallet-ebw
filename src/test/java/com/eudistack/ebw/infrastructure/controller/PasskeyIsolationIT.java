package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.controller.dto.PasskeyResponse;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration tests proving account- and tenant-level isolation for
 * {@link PasskeyController} GET {@code /api/v1/auth/passkeys} (EUD-143).
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-04 — a holder of account A never receives devices belonging to account B,
 *   whether B is in the same tenant or a different one.</li>
 *   <li>ES-05 — the list is resolved solely from the token identity; attempts to
 *   influence the target account via request parameters have no effect, and no
 *   existence/count of another account's devices is leaked.</li>
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
class PasskeyIsolationIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT_1 = "pskisoa";
    private static final String TENANT_2 = "pskisob";
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
                    .withDatabaseName("passkey_isolation_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/passkey_isolation_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/passkey_isolation_it");
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

    private void seedPasskey(String schema, UUID userId, String credentialId, String displayName)
            throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".user_passkey "
                    + "(id, user_id, credential_id, display_name, user_agent, created_at, last_used_at) VALUES ('"
                    + UUID.randomUUID() + "', '" + userId + "', '" + credentialId + "', '"
                    + displayName.replace("'", "''")
                    + "', 'test-agent', '2026-01-01T10:00:00Z', NULL)");
        }
    }

    private WebTestClient.ResponseSpec listWithAuth(String host, String bearer, String rawQuery) {
        String uri = "/api/v1/auth/passkeys" + (rawQuery == null ? "" : rawQuery);
        return webClient.get()
                .uri(uri)
                .header("Host", host)
                .header("Authorization", "Bearer " + bearer)
                .exchange();
    }

    // -------------------------------------------------------------------------
    // AC-04 — same tenant, two accounts: A never sees B's devices
    // -------------------------------------------------------------------------

    @Test
    void list_sameTenantTwoAccounts_accountAOnlySeesOwnDevices() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedPasskey(SCHEMA_1, USER_A, "cred-a-1", "A's iPhone");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-1", "B's Pixel");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-2", "B's MacBook");

        List<PasskeyResponse> body = listWithAuth(HOST_1, TOKEN_USER_A, null)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).hasSize(1);
        assertThat(body.get(0).displayName()).isEqualTo("A's iPhone");
        assertThat(body).extracting(PasskeyResponse::displayName)
                .doesNotContain("B's Pixel", "B's MacBook");
    }

    // -------------------------------------------------------------------------
    // AC-04 — different tenants, same userId: no cross-tenant leakage
    // -------------------------------------------------------------------------

    @Test
    void list_sameUserIdDifferentTenants_noCrossTenantLeakage() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@tenant1.com");
        seedUser(SCHEMA_2, USER_A, "user-a@tenant2.com");
        seedPasskey(SCHEMA_1, USER_A, "cred-tenant1", "Tenant 1 Device");
        seedPasskey(SCHEMA_2, USER_A, "cred-tenant2", "Tenant 2 Device");

        List<PasskeyResponse> tenant1Body = listWithAuth(HOST_1, TOKEN_USER_A, null)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(tenant1Body).hasSize(1);
        assertThat(tenant1Body.get(0).displayName()).isEqualTo("Tenant 1 Device");

        List<PasskeyResponse> tenant2Body = listWithAuth(HOST_2, TOKEN_USER_A, null)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(tenant2Body).hasSize(1);
        assertThat(tenant2Body.get(0).displayName()).isEqualTo("Tenant 2 Device");
    }

    // -------------------------------------------------------------------------
    // ES-05 — resolution is strictly by token identity, never by request parameter
    // -------------------------------------------------------------------------

    @Test
    void list_attemptToForceAnotherAccountViaQueryParam_isIgnored() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedPasskey(SCHEMA_1, USER_A, "cred-a-1", "A's iPhone");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-1", "B's Pixel");

        List<PasskeyResponse> body = listWithAuth(HOST_1, TOKEN_USER_A, "?userId=" + USER_B)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).hasSize(1);
        assertThat(body.get(0).displayName()).isEqualTo("A's iPhone");
    }

    // -------------------------------------------------------------------------
    // ES-05 — no existence/count of another account's devices is leaked
    // -------------------------------------------------------------------------

    @Test
    void list_accountWithNoDevices_returnsEmptyRegardlessOfOtherAccountsDeviceCount()
            throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-1", "B's Pixel");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-2", "B's MacBook");
        seedPasskey(SCHEMA_1, USER_B, "cred-b-3", "B's iPad");

        List<PasskeyResponse> body = listWithAuth(HOST_1, TOKEN_USER_A, null)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).isEmpty();
    }
}
