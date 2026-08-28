package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.controller.dto.ActivityResponse;
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
import java.sql.Statement;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration tests for {@link ActivityController} (EUD-141 — server-mode activity sync)
 * using the full Spring Boot context with a real PostgreSQL container.
 *
 * <p>{@link TokenSigner} is mocked so JWT auth can be exercised without a running key pair.
 * Tenant resolution is exercised for real via the {@code Host} header — schema-per-tenant
 * routing sets the R2DBC {@code search_path} from the Reactor context.
 *
 * <p>Covered scenarios:
 * <ul>
 *   <li>Happy path — persistence, recovery from a server-side copy, multi-device sync,
 *       empty history for a brand-new holder (FR-14/FR-15/FR-16).</li>
 *   <li>Idempotency (duplicate POST), concurrency (two devices racing on the same event id),
 *       convergence on the {@code MAX_ENTRIES=200} cap (NFR-A-02).</li>
 *   <li>Input validation — malformed payloads rejected with 400, no side effects.</li>
 *   <li>Isolation &amp; authentication — 401 without/with an invalid token, cross-holder and
 *       cross-tenant isolation, a forged id belonging to another holder is a no-op (NFR-S-01).</li>
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
class ActivityControllerIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT_1 = "actisoa";
    private static final String TENANT_2 = "actisob";
    private static final String SCHEMA_1 = TENANT_1 + SCHEMA_SUFFIX;
    private static final String SCHEMA_2 = TENANT_2 + SCHEMA_SUFFIX;
    private static final String HOST_1 = TENANT_1 + ".eudistack.net";
    private static final String HOST_2 = TENANT_2 + ".eudistack.net";

    private static final String TOKEN_A = "token-user-a";
    private static final String TOKEN_B = "token-user-b";
    private static final String INVALID_TOKEN = "invalid-token";

    private static final UUID USER_A = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID USER_B = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("activity_ctrl_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/activity_ctrl_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/activity_ctrl_it");
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
        when(tokenSigner.verify(TOKEN_A)).thenReturn(
                Map.of("sub", USER_A.toString(), "email", "user-a@test.com"));
        when(tokenSigner.verify(TOKEN_B)).thenReturn(
                Map.of("sub", USER_B.toString(), "email", "user-b@test.com"));
        when(tokenSigner.verify(INVALID_TOKEN)).thenThrow(new InvalidTokenException());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void cleanTables(String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM " + schema + ".wallet_activity");
            stmt.execute("DELETE FROM " + schema + ".refresh_token");
            stmt.execute("DELETE FROM " + schema + ".user_passkey");
            stmt.execute("DELETE FROM " + schema + ".wallet_user");
        }
    }

    private void seedUser(String schema, UUID userId, String email) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".wallet_user (id, email) VALUES ('"
                    + userId + "', '" + email + "') ON CONFLICT (id) DO NOTHING");
        }
    }

    private void seedActivity(String schema, UUID id, UUID userId, String type, String credentialName,
                               String counterparty, Instant createdAt) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".wallet_activity "
                    + "(id, user_id, type, credential_name, counterparty, created_at) VALUES ('"
                    + id + "', '" + userId + "', '" + type + "', '"
                    + credentialName.replace("'", "''") + "', '"
                    + counterparty.replace("'", "''") + "', '" + createdAt + "')");
        }
    }

    /** Bulk-seeds {@code count} activity rows for {@code userId}, one second apart, starting at {@code base}. */
    private void seedManyActivities(String schema, UUID userId, Instant base, int count) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             Statement stmt = conn.createStatement()) {
            for (int i = 0; i < count; i++) {
                var createdAt = base.plusSeconds(i);
                stmt.addBatch(
                        "INSERT INTO " + schema + ".wallet_activity "
                        + "(id, user_id, type, credential_name, counterparty, created_at) VALUES ('"
                        + UUID.randomUUID() + "', '" + userId + "', 'ISSUED', 'cred-"
                        + String.format("%03d", i) + "', 'issuer', '" + createdAt + "')");
            }
            stmt.executeBatch();
        }
    }

    private Map<String, Object> validBody(UUID id) {
        var body = new HashMap<String, Object>();
        body.put("id", id.toString());
        body.put("type", "ISSUED");
        body.put("credential_name", "LEARCredentialEmployee");
        body.put("counterparty", "https://issuer.example.com");
        body.put("details", "issued via OID4VCI");
        body.put("shared_attributes", List.of("given_name", "family_name"));
        return body;
    }

    private WebTestClient.ResponseSpec postActivity(String host, String bearer, Map<String, Object> body) {
        var request = webClient.post().uri("/api/v1/activity").header("Host", host);
        if (bearer != null) {
            request = request.header("Authorization", "Bearer " + bearer);
        }
        return request.bodyValue(body).exchange();
    }

    private WebTestClient.ResponseSpec listActivity(String host, String bearer) {
        var request = webClient.get().uri("/api/v1/activity").header("Host", host);
        if (bearer != null) {
            request = request.header("Authorization", "Bearer " + bearer);
        }
        return request.exchange();
    }

    // ===========================================================================
    // Happy path — recuperación, sync entre dispositivos, persistencia, historial vacío
    // ===========================================================================

    @Test
    void record_newActivity_persistsAndIsRetrievableViaList() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var id = UUID.randomUUID();

        postActivity(HOST_1, TOKEN_A, validBody(id))
                .expectStatus().isCreated()
                .expectBody(ActivityResponse.class)
                .value(activity -> {
                    assertThat(activity.id()).isEqualTo(id);
                    assertThat(activity.type()).isEqualTo("ISSUED");
                    assertThat(activity.credentialName()).isEqualTo("LEARCredentialEmployee");
                    assertThat(activity.counterparty()).isEqualTo("https://issuer.example.com");
                    assertThat(activity.sharedAttributes()).containsExactly("given_name", "family_name");
                    assertThat(activity.createdAt()).isNotNull();
                });

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(1);
        assertThat(history.get(0).id()).isEqualTo(id);
    }

    @Test
    void list_newHolderWithNoActivity_returnsEmptyHistory() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).isEmpty();
    }

    @Test
    void list_activitySeededFromPreviousSession_recoversFullHistoryAsSourceOfTruth() throws SQLException {
        // Simulates FR-15: the browser's local copy was lost, but the server already
        // holds these events from a previous session — they must be recoverable in full.
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_A, "ISSUED", "cred-1", "issuer-1",
                Instant.parse("2026-01-01T10:00:00Z"));
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_A, "PRESENTED", "cred-1", "verifier-1",
                Instant.parse("2026-01-02T10:00:00Z"));

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(2);
        assertThat(history).extracting(ActivityResponse::type).containsExactlyInAnyOrder("ISSUED", "PRESENTED");
    }

    @Test
    void sync_twoDevicesRecordingDifferentEvents_bothConvergeInSharedHistory() throws SQLException {
        // FR-16: two devices of the same holder each record one local event; both must
        // end up visible from either device once synced through the server.
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var deviceOneEvent = UUID.randomUUID();
        var deviceTwoEvent = UUID.randomUUID();

        postActivity(HOST_1, TOKEN_A, validBody(deviceOneEvent)).expectStatus().isCreated();
        var deviceTwoBody = validBody(deviceTwoEvent);
        deviceTwoBody.put("type", "PRESENTED");
        deviceTwoBody.put("counterparty", "https://verifier.example.com");
        postActivity(HOST_1, TOKEN_A, deviceTwoBody).expectStatus().isCreated();

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).extracting(ActivityResponse::id)
                .containsExactlyInAnyOrder(deviceOneEvent, deviceTwoEvent);
    }

    // ===========================================================================
    // Idempotencia (POST x2), concurrencia (dos dispositivos), cap MAX_ENTRIES=200
    // ===========================================================================

    @Test
    void record_samePayloadPostedTwice_isIdempotentAndDoesNotDuplicate() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var id = UUID.randomUUID();
        var body = validBody(id);

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isCreated();
        postActivity(HOST_1, TOKEN_A, body).expectStatus().isCreated();

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(1);
        assertThat(history.get(0).id()).isEqualTo(id);
    }

    @Test
    void record_twoDevicesRaceToSyncSameEventId_onlyOneRowIsPersisted() throws Exception {
        // Two devices independently decide to sync the same locally-generated event at
        // the same time; the DB-level ON CONFLICT DO NOTHING must make this race safe.
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var id = UUID.randomUUID();
        var body = validBody(id);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> deviceOne = executor.submit(() ->
                    postActivity(HOST_1, TOKEN_A, body).expectStatus().is2xxSuccessful());
            Future<?> deviceTwo = executor.submit(() ->
                    postActivity(HOST_1, TOKEN_A, body).expectStatus().is2xxSuccessful());
            deviceOne.get(10, TimeUnit.SECONDS);
            deviceTwo.get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdown();
        }

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(1);
        assertThat(history.get(0).id()).isEqualTo(id);
    }

    @Test
    void list_moreThan200Entries_convergesOnThe200MostRecent() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var base = Instant.parse("2026-01-01T00:00:00Z");
        seedManyActivities(SCHEMA_1, USER_A, base, 205);

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(200);
        // Most recent (i = 204) first; the 5 oldest (i = 0..4) fall outside the cap.
        assertThat(history.get(0).credentialName()).isEqualTo("cred-204");
        assertThat(history).extracting(ActivityResponse::credentialName)
                .doesNotContain("cred-000", "cred-001", "cred-002", "cred-003", "cred-004");
    }

    // ===========================================================================
    // Validación de input inválido (400)
    // ===========================================================================

    @Test
    void record_missingId_returns400() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var body = validBody(UUID.randomUUID());
        body.remove("id");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();
    }

    @Test
    void record_blankType_returns400() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var body = validBody(UUID.randomUUID());
        body.put("type", "");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();
    }

    @Test
    void record_unknownTypeValue_returns400() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var id = UUID.randomUUID();
        var body = validBody(id);
        body.put("type", "BOGUS");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();

        assertThat(listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody()).isEmpty();
    }

    @Test
    void record_blankCredentialName_returns400() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var body = validBody(UUID.randomUUID());
        body.put("credential_name", "  ");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();
    }

    @Test
    void record_blankCounterparty_returns400() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var body = validBody(UUID.randomUUID());
        body.put("counterparty", "");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();
    }

    @Test
    void record_invalidPayload_doesNotCreateAnyRow() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        var body = validBody(UUID.randomUUID());
        body.put("type", "NOT_A_TYPE");

        postActivity(HOST_1, TOKEN_A, body).expectStatus().isBadRequest();

        assertThat(listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody()).isEmpty();
    }

    // ===========================================================================
    // Suite de aislamiento holder/tenant + autenticación
    // ===========================================================================

    @Test
    void record_noAuthorizationHeader_returns401() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");

        postActivity(HOST_1, null, validBody(UUID.randomUUID())).expectStatus().isUnauthorized();
    }

    @Test
    void record_invalidToken_returns401() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");

        postActivity(HOST_1, INVALID_TOKEN, validBody(UUID.randomUUID())).expectStatus().isUnauthorized();
    }

    @Test
    void list_noAuthorizationHeader_returns401WithNoData() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_A, "ISSUED", "cred-1", "issuer-1", Instant.now());

        listActivity(HOST_1, null).expectStatus().isUnauthorized().expectBody().isEmpty();
    }

    @Test
    void list_sameTenantTwoHolders_holderAOnlySeesOwnActivity() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_A, "ISSUED", "A's credential", "issuer-1", Instant.now());
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_B, "ISSUED", "B's credential", "issuer-1", Instant.now());

        List<ActivityResponse> history = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(history).hasSize(1);
        assertThat(history.get(0).credentialName()).isEqualTo("A's credential");
    }

    @Test
    void list_sameUserIdDifferentTenants_noCrossTenantLeakage() throws SQLException {
        // Same UUID reused across two tenant schemas on purpose — proves isolation comes
        // from the schema-per-tenant boundary, not merely from userId equality.
        seedUser(SCHEMA_1, USER_A, "user-a@tenant1.com");
        seedUser(SCHEMA_2, USER_A, "user-a@tenant2.com");
        seedActivity(SCHEMA_1, UUID.randomUUID(), USER_A, "ISSUED", "Tenant 1 credential", "issuer-1", Instant.now());
        seedActivity(SCHEMA_2, UUID.randomUUID(), USER_A, "ISSUED", "Tenant 2 credential", "issuer-1", Instant.now());

        List<ActivityResponse> tenant1History = listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();
        assertThat(tenant1History).hasSize(1);
        assertThat(tenant1History.get(0).credentialName()).isEqualTo("Tenant 1 credential");

        List<ActivityResponse> tenant2History = listActivity(HOST_2, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();
        assertThat(tenant2History).hasSize(1);
        assertThat(tenant2History.get(0).credentialName()).isEqualTo("Tenant 2 credential");
    }

    @Test
    void record_forgedIdBelongingToAnotherHolder_isIgnoredAndDoesNotLeakOrOverwrite() throws SQLException {
        seedUser(SCHEMA_1, USER_A, "user-a@test.com");
        seedUser(SCHEMA_1, USER_B, "user-b@test.com");
        var sharedId = UUID.randomUUID();
        // This row already belongs to holder B from a legitimate sync.
        seedActivity(SCHEMA_1, sharedId, USER_B, "ISSUED", "B's original credential", "issuer-b",
                Instant.parse("2026-01-01T10:00:00Z"));

        // Holder A submits a forged/collided id, attempting to piggyback on an existing row.
        var forgedBody = validBody(sharedId);
        forgedBody.put("credential_name", "attacker payload");
        postActivity(HOST_1, TOKEN_A, forgedBody).expectStatus().isCreated();

        // A never gains visibility over the row — insertIfAbsent was a no-op for A.
        assertThat(listActivity(HOST_1, TOKEN_A)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody()).isEmpty();

        // B's original row is untouched — not overwritten by A's payload.
        List<ActivityResponse> bHistory = listActivity(HOST_1, TOKEN_B)
                .expectStatus().isOk()
                .expectBodyList(ActivityResponse.class)
                .returnResult()
                .getResponseBody();
        assertThat(bHistory).hasSize(1);
        assertThat(bHistory.get(0).credentialName()).isEqualTo("B's original credential");
    }
}
