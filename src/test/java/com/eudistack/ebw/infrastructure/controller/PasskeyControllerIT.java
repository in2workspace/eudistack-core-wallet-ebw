package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@link PasskeyController} GET {@code /api/v1/auth/passkeys}
 * using the full Spring Boot context with a real PostgreSQL container.
 *
 * <p>{@link TokenSigner} is mocked so JWT auth can be exercised without a running key pair.
 * Tenant resolution is exercised for real via the {@code Host} header — schema-per-tenant
 * routing sets the R2DBC {@code search_path} from the Reactor context.
 *
 * <p>Covered criteria (EUD-143):
 * <ul>
 *   <li>AC-01 — list returns exactly the passkeys registered under the caller's account</li>
 *   <li>AC-02 — each entry exposes displayName / createdAt / lastUsedAt</li>
 *   <li>EC-02 — lastUsedAt absent (never used) is returned as {@code null}, not an error</li>
 *   <li>EC-04 — result order is stable: last_used_at DESC NULLS LAST, created_at DESC</li>
 *   <li>ES-01 — no Authorization header / invalid token → 401, no passkey data returned</li>
 * </ul>
 *
 * <p>Covered criteria (EUD-144, {@code DELETE /api/v1/auth/passkeys/{id}}):
 * <ul>
 *   <li>AC-01 — revoking a device other than the last one deletes its passkey (204)</li>
 *   <li>ES-01 — no Authorization header / invalid token → 401, passkey not deleted</li>
 *   <li>ES-02 — nonexistent or not-owned passkey id → 404, anti-enumeration (same response either way)</li>
 *   <li>EC-01 / ES-03 — deleting the account's only passkey → 409, passkey not deleted</li>
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
class PasskeyControllerIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT = "pskctrlit";
    private static final String SCHEMA = TENANT + SCHEMA_SUFFIX;
    private static final String HOST_HEADER = TENANT + ".eudistack.net";
    private static final String VALID_TOKEN = "valid-bearer-token";
    private static final String INVALID_TOKEN = "invalid-bearer-token";
    private static final String VALID_TOKEN_B = "valid-bearer-token-b";
    private static final UUID USER_A = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID USER_B = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("passkey_ctrl_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/passkey_ctrl_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/passkey_ctrl_it");
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
        when(tokenSigner.verify(VALID_TOKEN_B)).thenReturn(
                Map.of("sub", USER_B.toString(), "email", "user-b@test.com"));
        when(tokenSigner.verify(INVALID_TOKEN)).thenThrow(new InvalidTokenException());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void cleanTables() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
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

    private void seedPasskey(UUID id, UUID userId, String credentialId, String displayName,
                             Instant createdAt, Instant lastUsedAt) throws SQLException {
        String lastUsedSql = lastUsedAt == null ? "NULL" : "'" + lastUsedAt + "'";
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + SCHEMA + ".user_passkey "
                    + "(id, user_id, credential_id, display_name, user_agent, created_at, last_used_at) VALUES ('"
                    + id + "', '" + userId + "', '" + credentialId + "', '" + displayName
                    + "', 'test-agent', '" + createdAt + "', " + lastUsedSql + ")");
        }
    }

    private WebTestClient.ResponseSpec listWithAuth(String bearer) {
        var request = webClient.get()
                .uri("/api/v1/auth/passkeys")
                .header("Host", HOST_HEADER);
        if (bearer != null) {
            request = request.header("Authorization", "Bearer " + bearer);
        }
        return request.exchange();
    }

    private WebTestClient.ResponseSpec deleteWithAuth(UUID id, String bearer) {
        var request = webClient.delete()
                .uri("/api/v1/auth/passkeys/{id}", id)
                .header("Host", HOST_HEADER);
        if (bearer != null) {
            request = request.header("Authorization", "Bearer " + bearer);
        }
        return request.exchange();
    }

    // -------------------------------------------------------------------------
    // AC-01 — list returns exactly the passkeys of the authenticated account
    // -------------------------------------------------------------------------

    @Test
    void list_authenticatedUserWithPasskeys_returnsAllOfThem() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), Instant.parse("2026-06-01T10:00:00Z"));
        seedPasskey(UUID.randomUUID(), USER_A, "cred-2", "Pixel 8",
                Instant.parse("2026-01-02T10:00:00Z"), Instant.parse("2026-05-01T10:00:00Z"));
        seedPasskey(UUID.randomUUID(), USER_A, "cred-3", "MacBook Pro",
                Instant.parse("2026-01-03T10:00:00Z"), null);

        List<PasskeyResponse> body = listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).hasSize(3);
    }

    // -------------------------------------------------------------------------
    // AC-02 — each entry exposes displayName / createdAt / lastUsedAt
    // -------------------------------------------------------------------------

    @Test
    void list_returnsDisplayNameCreatedAtAndLastUsedAt() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        Instant createdAt = Instant.parse("2026-01-01T10:00:00Z");
        Instant lastUsedAt = Instant.parse("2026-06-01T10:00:00Z");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "iPhone 15", createdAt, lastUsedAt);

        List<PasskeyResponse> body = listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).hasSize(1);
        PasskeyResponse passkey = body.get(0);
        assertThat(passkey.displayName()).isEqualTo("iPhone 15");
        assertThat(passkey.createdAt()).isEqualTo(createdAt);
        assertThat(passkey.lastUsedAt()).isEqualTo(lastUsedAt);
    }

    // -------------------------------------------------------------------------
    // EC-02 — lastUsedAt absent (never used) is returned as null, not an error
    // -------------------------------------------------------------------------

    @Test
    void list_passkeyNeverUsed_returnsNullLastUsedAtWithoutError() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "MacBook Pro",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        List<PasskeyResponse> body = listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).hasSize(1);
        assertThat(body.get(0).lastUsedAt()).isNull();
    }

    // -------------------------------------------------------------------------
    // EC-04 — stable order: last_used_at DESC NULLS LAST, created_at DESC
    // -------------------------------------------------------------------------

    @Test
    void list_multiplePasskeys_returnsStableOrderByLastUsedThenCreatedAt() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        // Inserted out of expected-output order on purpose.
        seedPasskey(UUID.randomUUID(), USER_A, "cred-never-used", "Never Used Device",
                Instant.parse("2026-01-02T10:00:00Z"), null);
        seedPasskey(UUID.randomUUID(), USER_A, "cred-most-recent", "Most Recently Used",
                Instant.parse("2026-01-01T10:00:00Z"), Instant.parse("2026-06-01T10:00:00Z"));
        seedPasskey(UUID.randomUUID(), USER_A, "cred-less-recent", "Less Recently Used",
                Instant.parse("2026-01-03T10:00:00Z"), Instant.parse("2026-05-01T10:00:00Z"));

        List<PasskeyResponse> body = listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(body).extracting(PasskeyResponse::displayName)
                .containsExactly("Most Recently Used", "Less Recently Used", "Never Used Device");
    }

    // -------------------------------------------------------------------------
    // ES-01 — no Authorization header → 401, no passkey data
    // -------------------------------------------------------------------------

    @Test
    void list_noAuthorizationHeader_returns401WithNoData() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        listWithAuth(null)
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    // -------------------------------------------------------------------------
    // ES-01 — invalid / unverifiable token → 401, no passkey data
    // -------------------------------------------------------------------------

    @Test
    void list_invalidToken_returns401WithNoData() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        listWithAuth(INVALID_TOKEN)
                .expectStatus().isUnauthorized()
                .expectBody().isEmpty();
    }

    // ===========================================================================
    // EUD-144 — DELETE /api/v1/auth/passkeys/{id}
    // ===========================================================================

    // -------------------------------------------------------------------------
    // AC-01 — revoking a device other than the last one deletes its passkey
    // -------------------------------------------------------------------------

    @Test
    void delete_targetOfTwoPasskeys_returns204AndRemovesOnlyTheTarget() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-target", "Old Phone",
                Instant.parse("2026-01-01T10:00:00Z"), null);
        seedPasskey(UUID.randomUUID(), USER_A, "cred-remaining", "Laptop",
                Instant.parse("2026-01-02T10:00:00Z"), null);

        deleteWithAuth(target, VALID_TOKEN)
                .expectStatus().isNoContent();

        List<PasskeyResponse> remaining = listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody();
        assertThat(remaining).extracting(PasskeyResponse::displayName).containsExactly("Laptop");
    }

    // -------------------------------------------------------------------------
    // ES-01 — no Authorization header / invalid token → 401, passkey not deleted
    // -------------------------------------------------------------------------

    @Test
    void delete_noAuthorizationHeader_returns401AndDoesNotDelete() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);
        seedPasskey(UUID.randomUUID(), USER_A, "cred-2", "Laptop",
                Instant.parse("2026-01-02T10:00:00Z"), null);

        deleteWithAuth(target, null)
                .expectStatus().isUnauthorized();

        assertThat(listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody()).hasSize(2);
    }

    @Test
    void delete_invalidToken_returns401AndDoesNotDelete() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID target = UUID.randomUUID();
        seedPasskey(target, USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);
        seedPasskey(UUID.randomUUID(), USER_A, "cred-2", "Laptop",
                Instant.parse("2026-01-02T10:00:00Z"), null);

        deleteWithAuth(target, INVALID_TOKEN)
                .expectStatus().isUnauthorized();

        assertThat(listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody()).hasSize(2);
    }

    // -------------------------------------------------------------------------
    // ES-02 — nonexistent or not-owned passkey id → 404, anti-enumeration
    // (deeper cross-account/cross-tenant isolation matrix lives in
    // PasskeyRevocationIsolationIT, AC-05)
    // -------------------------------------------------------------------------

    @Test
    void delete_nonExistentPasskeyId_returns404() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedPasskey(UUID.randomUUID(), USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        deleteWithAuth(UUID.randomUUID(), VALID_TOKEN)
                .expectStatus().isNotFound();
    }

    @Test
    void delete_passkeyOwnedByAnotherAccount_returns404WithoutDeletingIt() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        seedUser(USER_B, "user-b@test.com");
        UUID otherAccountsPasskey = UUID.randomUUID();
        seedPasskey(otherAccountsPasskey, USER_B, "cred-b-1", "Second Account Phone",
                Instant.parse("2026-01-01T10:00:00Z"), null);
        // USER_A must have at least one passkey of their own, unrelated to this scenario.
        seedPasskey(UUID.randomUUID(), USER_A, "cred-a-1", "First Account Laptop",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        // USER_A attempts to delete a passkey that belongs to USER_B.
        deleteWithAuth(otherAccountsPasskey, VALID_TOKEN)
                .expectStatus().isNotFound();

        assertThat(listWithAuth(VALID_TOKEN_B)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody()).hasSize(1);
    }

    // -------------------------------------------------------------------------
    // EC-01 / ES-03 — deleting the account's only passkey → 409, not deleted
    // -------------------------------------------------------------------------

    @Test
    void delete_onlyPasskeyOfAccount_returns409AndDoesNotDelete() throws SQLException {
        seedUser(USER_A, "user-a@test.com");
        UUID onlyPasskey = UUID.randomUUID();
        seedPasskey(onlyPasskey, USER_A, "cred-1", "iPhone 15",
                Instant.parse("2026-01-01T10:00:00Z"), null);

        deleteWithAuth(onlyPasskey, VALID_TOKEN)
                .expectStatus().isEqualTo(409);

        assertThat(listWithAuth(VALID_TOKEN)
                .expectStatus().isOk()
                .expectBodyList(PasskeyResponse.class)
                .returnResult()
                .getResponseBody()).hasSize(1);
    }
}
