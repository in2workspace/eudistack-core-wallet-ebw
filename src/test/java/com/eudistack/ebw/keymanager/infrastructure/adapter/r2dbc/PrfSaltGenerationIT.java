package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.keymanager.application.PrfSaltService;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for PRF salt generation and persistence via {@link PrfSaltService}
 * backed by a real {@link PrfSaltRepository} against a Testcontainers PostgreSQL instance.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 — after init for {@code (H1, C1)}: exactly 1 row in {@code passkey_prf_salt}
 *       with 32-byte salt</li>
 *   <li>AC-02 — two credentials {@code (H1, C1)} and {@code (H1, C2)}: two distinct salts</li>
 *   <li>EC-01 — init twice for {@code (H1, C1)}: still 1 row, same salt returned both times
 *       (idempotent)</li>
 * </ul>
 *
 * <p>Follows the Testcontainers + Flyway + R2DBC setup pattern from
 * {@link PasskeyPrfPgDumpNonReconstructionIT}.</p>
 *
 * <p>Spec: EUDISTACK-537 T10; AC-01, AC-02, EC-01.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@ActiveProfiles("integration")
@Testcontainers
class PrfSaltGenerationIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT        = "prfsaltgen";
    private static final String TENANT_SCHEMA = TENANT + SCHEMA_SUFFIX;

    // H1: a valid UUID v4 that will be inserted into wallet_user first
    private static UUID HOLDER_1_UUID;
    private static String HOLDER_1;

    private static final String CRED_ID_1 = "cred-gen-1";
    private static final String CRED_ID_2 = "cred-gen-2";
    private static final String PASSKEY_1 = UUID.randomUUID().toString();

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_salt_gen_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/prf_salt_gen_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/prf_salt_gen_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired PrfSaltService prfSaltService;

    @BeforeAll
    static void provisionSchema() throws SQLException {
        HOLDER_1_UUID = UUID.randomUUID();
        HOLDER_1 = HOLDER_1_UUID.toString();

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
            // Ensure the holder exists in wallet_user (FK target)
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT_SCHEMA + ".wallet_user (id, email) "
                    + "VALUES ('" + HOLDER_1 + "', 'h1@test.com') "
                    + "ON CONFLICT (id) DO NOTHING");
            // Clear salt table before each test
            conn.createStatement().execute(
                    "INSERT INTO " + TENANT_SCHEMA + ".user_passkey (id, user_id, credential_id, display_name, attested_credential_data, "
                    + "sign_count, uv_initialized, backup_eligible, backup_state, prf_enabled) "
                    + "VALUES ('" + PASSKEY_1 + "', '" + HOLDER_1 + "', 'webauthn-cred-1', 'test passkey', "
                    + "decode('00', 'hex'), 0, true, false, false, true) "
                    + "ON CONFLICT (id) DO NOTHING");
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT_SCHEMA + ".passkey_prf_salt");
        }
    }

    // ------------------------------------------------------------------ AC-01

    @Test
    void createForPasskey_firstCall_persistsExactlyOneRowWith32ByteSalt() throws SQLException {
        StepVerifier.create(
                prfSaltService.createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)))
                .assertNext(salt -> assertThat(salt.value()).hasSize(32))
                .verifyComplete();

        // Verify exactly one row in the DB
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT prf_salt FROM " + TENANT_SCHEMA + ".passkey_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_1 + "' AND credential_id = '" + CRED_ID_1 + "'")) {
            assertThat(rs.next()).as("Expected one row after init").isTrue();
            byte[] storedSalt = rs.getBytes("prf_salt");
            assertThat(storedSalt).hasSize(32);
            assertThat(rs.next()).as("Expected only one row").isFalse();
        }
    }

    @Test
    void createForPasskey_firstCall_returnedSaltMatchesStoredSalt() throws SQLException {
        byte[] returnedSalt = prfSaltService
                .createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block().value();

        assertThat(returnedSalt).isNotNull().hasSize(32);

        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT prf_salt FROM " + TENANT_SCHEMA + ".passkey_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_1 + "' AND credential_id = '" + CRED_ID_1 + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getBytes("prf_salt")).isEqualTo(returnedSalt);
        }
    }

    // ------------------------------------------------------------------ AC-02

    @Test
    void createForPasskey_twoCredentialsSameHolder_produceTwoDistinctSalts() {
        byte[] salt1 = prfSaltService
                .createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block().value();

        byte[] salt2 = prfSaltService
                .createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_2)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block().value();

        assertThat(salt1).isNotNull().hasSize(32);
        assertThat(salt2).isNotNull().hasSize(32);
        assertThat(salt1).isNotEqualTo(salt2);
    }

    @Test
    void createForPasskey_twoCredentialsSameHolder_twoRowsInDb() throws SQLException {
        prfSaltService.createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block();
        prfSaltService.createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_2)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block();

        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + TENANT_SCHEMA + ".passkey_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_1 + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).isEqualTo(2);
        }
    }

    // ------------------------------------------------------------------ EC-01

    @Test
    void createForPasskey_calledTwiceForSameKey_returnsSameSalt() {
        byte[] first = prfSaltService
                .createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block().value();

        byte[] second = prfSaltService
                .createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block().value();

        assertThat(first).isNotNull().hasSize(32);
        assertThat(second).isNotNull().hasSize(32);
        assertThat(second).isEqualTo(first);
    }

    @Test
    void createForPasskey_calledTwiceForSameKey_onlyOneRowInDb() throws SQLException {
        prfSaltService.createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block();
        prfSaltService.createForPasskey(TENANT, HOLDER_1, PASSKEY_1, CRED_ID_1)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
                .block();

        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + TENANT_SCHEMA + ".passkey_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_1 + "' AND credential_id = '" + CRED_ID_1 + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).as("Idempotent re-init must not create a second row").isEqualTo(1);
        }
    }
}
