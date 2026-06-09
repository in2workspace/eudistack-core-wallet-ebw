package com.eudistack.ebw.keymanager.infrastructure.adapter.http;

import com.eudistack.ebw.domain.spi.TokenSigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Concurrency integration test covering EC-01: two simultaneous POST requests for the same
 * (tenant, holder, credential) tuple must both complete with 201, exactly one must carry the
 * {@code warning="existing_key_algorithm_used"} field, and exactly one row must be present
 * in {@code holder_key} after both requests settle.
 *
 * <p>The test uses the real key generation stack (no mocked ports except TokenSigner).
 * The PostgreSQL UPSERT ({@code INSERT … ON CONFLICT DO NOTHING RETURNING}) guarantees that
 * only the first writer creates the row; concurrent second writers receive the existing row
 * via a subsequent SELECT.
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class ConcurrentSameCredentialIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BEARER = "concurrent-same-bearer";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("concurrent_same_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/concurrent_same_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/concurrent_same_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @MockitoBean
    TokenSigner tokenSigner;

    @Autowired
    WebTestClient webClient;

    @Autowired
    ObjectMapper objectMapper;

    private String tenant;
    private String schema;
    private UUID holderId;

    @BeforeEach
    void setUp() throws SQLException {
        holderId = UUID.randomUUID();
        tenant = "t" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        schema = tenant + SCHEMA_SUFFIX;
        provisionTenantSchemaWithServerDbProfile();
        when(tokenSigner.verify(BEARER)).thenReturn(
                Map.of("sub", holderId.toString(), "email", "holder@test.com"));
    }

    // -------------------------------------------------------------------------
    // EC-01 — two concurrent requests for the same (holder, credential)
    // -------------------------------------------------------------------------

    @Test
    void concurrentRequests_sameCredential_bothReturn201_oneHasWarning_oneRowInDb()
            throws Exception {
        String credentialId = "cred-concurrent-same";
        String body = """
                {
                  "credential_id": "%s",
                  "format": "dc+sd-jwt",
                  "supported_algs": ["ES256"],
                  "issuer_identifier": "https://issuer.example.com"
                }
                """.formatted(credentialId);

        // Fire 2 requests concurrently on ForkJoinPool common pool threads
        CompletableFuture<byte[]> f1 = CompletableFuture.supplyAsync(() -> executePost(body));
        CompletableFuture<byte[]> f2 = CompletableFuture.supplyAsync(() -> executePost(body));

        byte[] r1 = f1.get(15, TimeUnit.SECONDS);
        byte[] r2 = f2.get(15, TimeUnit.SECONDS);

        @SuppressWarnings("unchecked")
        Map<String, Object> resp1 = objectMapper.readValue(r1, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> resp2 = objectMapper.readValue(r2, Map.class);

        List<Map<String, Object>> responses = List.of(resp1, resp2);

        // Both must succeed (201 returns a body)
        assertThat(responses).allSatisfy(r -> {
            assertThat(r).containsKey("key_id");
            assertThat(r).containsKey("public_jwk");
            assertThat(r).containsKey("jws_proof");
        });

        // Exactly one must carry the warning
        long withWarning = responses.stream()
                .filter(r -> "existing_key_algorithm_used".equals(r.get("warning")))
                .count();
        assertThat(withWarning)
                .as("exactly one response must carry warning=existing_key_algorithm_used (EC-01)")
                .isEqualTo(1);

        // Both responses must carry the same key_id (the idempotent key)
        assertThat(resp1.get("key_id")).isEqualTo(resp2.get("key_id"));

        // Exactly one row in the holder_key table
        int rowCount = countHolderKeyRows(credentialId);
        assertThat(rowCount)
                .as("exactly 1 holder_key row must exist after concurrent first-issuance (EC-01)")
                .isEqualTo(1);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private byte[] executePost(String body) {
        return webClient.post()
                .uri("/api/v1/keys/generate")
                .header("Host", tenant + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .returnResult()
                .getResponseBody();
    }

    private void provisionTenantSchemaWithServerDbProfile() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + schema);
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager) "
                    + "VALUES ('" + tenant + "', 'server', 'db') "
                    + "ON CONFLICT (tenant) DO NOTHING");
        }
    }

    private int countHolderKeyRows(String credentialId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + schema + ".holder_key "
                     + "WHERE holder_id = '" + holderId + "' "
                     + "AND credential_id = '" + credentialId + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }
}