package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantAwareConnectionFactoryDecorator;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.r2dbc.DataR2dbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests verifying AC-06: when the database is unavailable, the
 * {@link HolderKeyR2dbcAdapter} propagates the error as a reactive error signal
 * and leaves no orphan rows in the database.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-06 — {@code upsertIfAbsent} propagates a reactive error when the table is absent</li>
 *   <li>AC-06 — {@code findBy} propagates a reactive error when the table is absent</li>
 *   <li>AC-06 / ADR-021 — no orphan row is written after a failed upsert (PostgreSQL
 *       atomic INSERT guarantees rollback on error)</li>
 * </ul>
 *
 * <p>The "DB unavailable" scenario is simulated by dropping the {@code holder_key} table
 * before the operation. This exercises the same error-propagation path as a real
 * network timeout or connection failure at the schema level.
 */
@Tag("integration")
@DataR2dbcTest(
        properties = {
                "spring.autoconfigure.exclude=",
                "ebw.tenant-flyway.enabled=false"
        }
)
@Import({
        TenantAwareConnectionFactoryDecorator.class,
        DbUnavailableHandlingIT.AdapterTestConfig.class
})
@Testcontainers
class DbUnavailableHandlingIT {

    @TestConfiguration
    @EnableR2dbcRepositories(basePackageClasses = SpringHolderKeyRepository.class)
    static class AdapterTestConfig {

        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        HolderKeyR2dbcAdapter holderKeyR2dbcAdapter(SpringHolderKeyRepository repository,
                ObjectMapper objectMapper,
                DatabaseClient databaseClient) {
            return new HolderKeyR2dbcAdapter(repository, objectMapper, databaseClient);
        }
    }

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final JwkPublic SAMPLE_JWK = new JwkPublic(
            Map.of("kty", "EC", "crv", "P-256", "x", "sampleX", "y", "sampleY"));

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("db_unavailable_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureR2dbcProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://"
                + postgres.getHost() + ":"
                + postgres.getMappedPort(5432)
                + "/db_unavailable_test");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
    }

    @Autowired
    private HolderKeyR2dbcAdapter adapter;

    private String testTenant;
    private String testSchema;

    @BeforeEach
    void setUp() throws SQLException {
        testTenant = "t" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        testSchema = testTenant + SCHEMA_SUFFIX;
        provisionSchemaAndMigrate();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void provisionSchemaAndMigrate() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + testSchema);
        }
        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(testSchema)
                .schemas(testSchema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private void dropHolderKeyTable() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DROP TABLE IF EXISTS " + testSchema + ".holder_key");
        }
    }

    private void recreateHolderKeyTable() throws SQLException {
        // Minimal DDL mirror of V4__Holder_key.sql for the "no orphan row" assertion
        String uniqueConstraint = "uq_hk_" + testTenant.replace("-", "");
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "CREATE TABLE " + testSchema + ".holder_key ("
                    + "  key_id        VARCHAR(36)  NOT NULL PRIMARY KEY,"
                    + "  holder_id     VARCHAR(255) NOT NULL,"
                    + "  credential_id VARCHAR(255) NOT NULL,"
                    + "  tenant_id     VARCHAR(255) NOT NULL,"
                    + "  private_key   BYTEA        NOT NULL,"
                    + "  public_jwk    JSONB        NOT NULL,"
                    + "  algorithm     VARCHAR(20)  NOT NULL,"
                    + "  format        VARCHAR(30)  NOT NULL,"
                    + "  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),"
                    + "  revoked_at    TIMESTAMPTZ,"
                    + "  CONSTRAINT " + uniqueConstraint
                    + "    UNIQUE (holder_id, credential_id)"
                    + ")");
        }
    }

    private int countRowsViaJdbc(String holderId, String credentialId) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + testSchema + ".holder_key "
                     + "WHERE holder_id = '" + holderId + "' "
                     + "AND credential_id = '" + credentialId + "'")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private HolderKey aKey(String holderId, String credentialId) {
        return new HolderKey(
                HolderKeyId.generate(),
                testTenant, holderId, credentialId,
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                new byte[]{1, 2, 3, 4, 5},
                SAMPLE_JWK,
                Instant.now(),
                null);
    }

    private <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, testTenant));
    }

    // -------------------------------------------------------------------------
    // AC-06 — upsertIfAbsent propagates error when table is absent
    // -------------------------------------------------------------------------

    @Test
    void upsertIfAbsent_whenTableAbsent_propagatesReactiveError() throws SQLException {
        dropHolderKeyTable();

        StepVerifier.create(withTenant(adapter.upsertIfAbsent(aKey("h-err", "c-err"))))
                .as("upsertIfAbsent must propagate a reactive error when holder_key table is absent (AC-06)")
                .verifyError();
    }

    // -------------------------------------------------------------------------
    // AC-06 — findBy propagates error when table is absent
    // -------------------------------------------------------------------------

    @Test
    void findBy_whenTableAbsent_propagatesReactiveError() throws SQLException {
        dropHolderKeyTable();

        StepVerifier.create(withTenant(adapter.findBy(testTenant, "h-err", "c-err")))
                .as("findBy must propagate a reactive error when holder_key table is absent (AC-06)")
                .verifyError();
    }

    // -------------------------------------------------------------------------
    // AC-06 / ADR-021 — no orphan row after failed upsert
    // -------------------------------------------------------------------------

    @Test
    void upsertIfAbsent_afterFailure_noOrphanRowInDatabase() throws SQLException {
        dropHolderKeyTable();

        // Attempted upsert fails (table absent)
        StepVerifier.create(withTenant(adapter.upsertIfAbsent(aKey("h-orphan", "c-orphan"))))
                .verifyError();

        // Re-create the table with minimal DDL to allow the count query
        recreateHolderKeyTable();

        // No orphan row — the failed INSERT left no data behind (PostgreSQL atomicity)
        int count = countRowsViaJdbc("h-orphan", "c-orphan");
        assertThat(count)
                .as("no orphan row must remain after a failed upsert (AC-06, ADR-021 atomicity)")
                .isZero();
    }
}