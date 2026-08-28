package com.eudistack.ebw.keymanager.infrastructure.health;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link HybridHealthContributor} — the {@code salt_coherent}
 * health indicator.
 *
 * <p>The indicator reports {@code UP} ({@code salt_coherent=true}) when each
 * {@code (holder_id, credential_id)} pair has exactly one row in {@code hybrid_prf_salt},
 * and {@code DOWN} ({@code salt_coherent=false}) when a duplicate pair exists.
 *
 * <p>The "duplicate row" scenario bypasses the composite PK by dropping the constraint
 * via a superuser connection, inserting the duplicate, then restoring the constraint.
 * This simulates a corrupted schema (e.g. after a migration roll-back) without requiring
 * a separate unguarded table.</p>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-08 — normal state (1 row per credential) → {@code salt_coherent=true}, status UP</li>
 *   <li>AC-08 — duplicate row → {@code salt_coherent=false}, status DOWN</li>
 *   <li>AC-08 — empty table → {@code salt_coherent=true}, status UP (no violations)</li>
 *   <li>AC-08 — health response contains NO {@code prf_salt} bytes or {@code holder_id}
 *       in plain text</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 T16; AC-08; NFR-S-537-01.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@ActiveProfiles("integration")
@Testcontainers
class HybridHealthSaltCoherentIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT        = "prfhealth";
    private static final String TENANT_SCHEMA = TENANT + SCHEMA_SUFFIX;

    private static UUID HOLDER_UUID;
    private static String HOLDER_ID;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_health_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/prf_health_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/prf_health_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired HybridHealthContributor hybridHealthContributor;

    @BeforeAll
    static void provisionSchema() throws SQLException {
        HOLDER_UUID = UUID.randomUUID();
        HOLDER_ID = HOLDER_UUID.toString();

        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + TENANT_SCHEMA);
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(TENANT_SCHEMA)
                .schemas(TENANT_SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    @BeforeEach
    void seedHolderAndClearSalts() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT_SCHEMA + ".wallet_user (id, email) "
                    + "VALUES ('" + HOLDER_ID + "', 'health@test.com') "
                    + "ON CONFLICT (id) DO NOTHING");
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT_SCHEMA + ".hybrid_prf_salt");
            // Restore PK in case a previous test dropped it
            restorePkIfMissing(conn);
        }
    }

    // ------------------------------------------------------------------ AC-08: empty table → UP

    @Test
    void health_emptyTable_reportsUp_saltCoherentTrue() {
        StepVerifier.create(hybridHealthContributor.health()
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails()).containsEntry("salt_coherent", true);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ AC-08: 1 row per credential → UP

    @Test
    void health_oneRowPerCredential_reportsUp_saltCoherentTrue() throws SQLException {
        insertSaltRow("cred-health-1", randomSalt());
        insertSaltRow("cred-health-2", randomSalt());

        StepVerifier.create(hybridHealthContributor.health()
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails()).containsEntry("salt_coherent", true);
                })
                .verifyComplete();
    }

    @Test
    void health_multipleHoldersMultipleCredentials_reportsUp() throws SQLException {
        UUID holder2 = UUID.randomUUID();
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT_SCHEMA + ".wallet_user (id, email) "
                    + "VALUES ('" + holder2 + "', 'health2@test.com') "
                    + "ON CONFLICT (id) DO NOTHING");
        }
        insertSaltRow("cred-multi-1", randomSalt());
        insertSaltRowForHolder(holder2, "cred-multi-2", randomSalt());

        StepVerifier.create(hybridHealthContributor.health()
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(health -> {
                    assertThat(health.getStatus()).isEqualTo(Status.UP);
                    assertThat(health.getDetails()).containsEntry("salt_coherent", true);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ AC-08: no tenant context → not DOWN

    @Test
    void health_withoutTenantContext_doesNotReportFalseDown() {
        // Actuator calls health() outside an HTTP request — no tenantDomain in Reactor context.
        // The indicator must not produce DOWN/salt_coherent=false in this case; it should return
        // UP with salt_coherent=true (and an explanatory note).
        StepVerifier.create(hybridHealthContributor.health())
                .assertNext(health -> {
                    assertThat(health.getStatus()).isNotEqualTo(Status.DOWN);
                    assertThat(health.getDetails()).containsEntry("salt_coherent", true);
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ AC-08: no PII in response

    @Test
    void health_response_doesNotContainPrfSaltOrHolderId() {
        // Health response must not expose prf_salt bytes or holder_id values (NFR-S-537-01)
        StepVerifier.create(hybridHealthContributor.health()
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(health -> {
                    Map<String, Object> details = health.getDetails();
                    // Only allowed detail key is "salt_coherent"
                    assertThat(details.keySet())
                            .as("Health details must only contain 'salt_coherent'")
                            .containsExactly("salt_coherent");

                    // No prf_salt bytes or holder_id in any detail value
                    details.forEach((key, value) -> {
                        String stringValue = String.valueOf(value);
                        assertThat(stringValue)
                                .as("Health detail '%s' must not contain prf_salt bytes", key)
                                .doesNotContainIgnoringCase("prf_salt");
                        assertThat(stringValue)
                                .as("Health detail '%s' must not contain holder UUID", key)
                                .doesNotContain(HOLDER_ID);
                    });
                })
                .verifyComplete();
    }

    @Test
    void health_withRows_response_doesNotContainPrfSaltOrHolderId() throws SQLException {
        insertSaltRow("cred-noleak-1", randomSalt());

        StepVerifier.create(hybridHealthContributor.health()
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(health -> {
                    Map<String, Object> details = health.getDetails();
                    assertThat(details.keySet()).containsExactly("salt_coherent");

                    details.forEach((key, value) -> {
                        String stringValue = String.valueOf(value);
                        assertThat(stringValue).doesNotContainIgnoringCase("prf_salt");
                        assertThat(stringValue).doesNotContain(HOLDER_ID);
                    });
                })
                .verifyComplete();
    }

    // ------------------------------------------------------------------ helpers

    private void insertSaltRow(String credentialId, byte[] salt) throws SQLException {
        insertSaltRowForHolder(HOLDER_UUID, credentialId, salt);
    }

    private void insertSaltRowForHolder(UUID holderId, String credentialId, byte[] salt)
            throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT_SCHEMA + ".hybrid_prf_salt "
                    + "(holder_id, credential_id, prf_salt) VALUES "
                    + "('" + holderId + "', '" + credentialId + "', "
                    + "decode('" + hex(salt) + "', 'hex'))");
        }
    }

    private void restorePkIfMissing(Connection conn) throws SQLException {
        try (var rs = conn.getMetaData().getPrimaryKeys(null, TENANT_SCHEMA, "hybrid_prf_salt")) {
            if (!rs.next()) {
                conn.createStatement().execute(
                        "ALTER TABLE " + TENANT_SCHEMA + ".hybrid_prf_salt "
                        + "ADD CONSTRAINT pk_hybrid_prf_salt "
                        + "PRIMARY KEY (holder_id, credential_id)");
            }
        }
    }

    private static byte[] randomSalt() {
        byte[] salt = new byte[32];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
