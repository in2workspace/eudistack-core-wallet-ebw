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
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Integration test covering ES-03: when a second issuance request arrives for an existing
 * (holder, credential) tuple but proposes a different algorithm, the adapter must return the
 * <em>original</em> key (preserved algorithm) together with
 * {@code warning="existing_key_algorithm_used"}.
 *
 * <p>The test issues a first request with {@code ES256} and a second request with
 * {@code EdDSA} for the same credential. The response for the second request must:
 * <ul>
 *   <li>Return 201 Created with the <em>same</em> {@code key_id} as the first response.</li>
 *   <li>Carry {@code warning="existing_key_algorithm_used"}.</li>
 *   <li>Carry a public JWK with {@code crv=P-256} (ES256 curve, not Ed25519), proving the
 *       original algorithm was preserved.</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-119 ES-03, ADR-021 (one key per composite key tuple).
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class AlgorithmChangeRequestIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BEARER = "alg-change-bearer";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("alg_change_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/alg_change_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/alg_change_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("ebw.encryption.key", () -> "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=");
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
    // ES-03 — second request with different algorithm returns existing key + warning
    // -------------------------------------------------------------------------

    @Test
    void secondRequest_differentAlgorithm_returnsExistingKeyWithWarning() throws Exception {
        String credentialId = "cred-alg-change";

        // First request: ES256 → creates a new key (P-256 curve)
        byte[] firstRaw = webClient.post()
                .uri("/api/v1/keys/generate")
                .header("Host", tenant + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody(credentialId, "ES256"))
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .returnResult()
                .getResponseBody();

        @SuppressWarnings("unchecked")
        Map<String, Object> first = objectMapper.readValue(firstRaw, Map.class);
        String firstKeyId = (String) first.get("key_id");

        assertThat(first.get("warning"))
                .as("first request must not carry a warning")
                .isNull();

        // Second request: EdDSA for the same credential → must return the original ES256 key
        byte[] secondRaw = webClient.post()
                .uri("/api/v1/keys/generate")
                .header("Host", tenant + ".eudistack.net")
                .header("Authorization", "Bearer " + BEARER)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody(credentialId, "EdDSA"))
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .returnResult()
                .getResponseBody();

        @SuppressWarnings("unchecked")
        Map<String, Object> second = objectMapper.readValue(secondRaw, Map.class);

        assertThat(second.get("key_id"))
                .as("second request must return the same key_id as the first (ES-03 / ADR-021)")
                .isEqualTo(firstKeyId);

        assertThat(second.get("warning"))
                .as("second request must carry warning (ES-03)")
                .isEqualTo("existing_key_algorithm_used");

        // The public JWK must still show P-256 (ES256 curve, NOT Ed25519)
        @SuppressWarnings("unchecked")
        Map<String, Object> publicJwk = (Map<String, Object>) second.get("public_jwk");
        assertThat(publicJwk.get("crv"))
                .as("original ES256 curve (P-256) must be preserved, not replaced by EdDSA (ES-03)")
                .isEqualTo("P-256");

        // Verify DB has exactly 1 row (no second row was created)
        int rowCount = countHolderKeyRows(credentialId);
        assertThat(rowCount)
                .as("only 1 row must exist in holder_key regardless of algorithm change attempt (ADR-021)")
                .isEqualTo(1);

        // And the stored algorithm must be ES256
        String storedAlgorithm = readStoredAlgorithm(credentialId);
        assertThat(storedAlgorithm)
                .as("stored algorithm must remain ES256, not be overwritten by EdDSA request (ADR-021)")
                .isEqualTo("ES256");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String requestBody(String credentialId, String algorithm) {
        return """
                {
                  "credential_id": "%s",
                  "format": "dc+sd-jwt",
                  "supported_algs": ["%s"],
                  "issuer_identifier": "https://issuer.example.com"
                }
                """.formatted(credentialId, algorithm);
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

    private String readStoredAlgorithm(String credentialId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT algorithm FROM " + schema + ".holder_key "
                     + "WHERE holder_id = '" + holderId + "' "
                     + "AND credential_id = '" + credentialId + "'")) {
            assertThat(rs.next()).isTrue();
            return rs.getString("algorithm");
        }
    }
}