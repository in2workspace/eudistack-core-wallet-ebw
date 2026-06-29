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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.function.Tuple2;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrency integration tests for the get-or-create PRF salt path.
 *
 * <p>Two simultaneous {@code getOrCreatePrfSalt(tenant, H1, C1)} calls race to insert
 * the first salt for a fresh {@code (H1, C1)} key. The composite PK constraint in
 * {@code hybrid_prf_salt} is the sole uniqueness guard: the losing INSERT is silently
 * swallowed by {@link PrfSaltRepository} (duplicate-key → {@code Mono.empty()}); the
 * loser then re-SELECTs and returns the winner's value (EC-03, R-3).</p>
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>EC-03 — two concurrent init calls for the same {@code (H1, C1)} → exactly 1 row
 *       in DB; both callers receive the same salt; no 500 error propagated</li>
 *   <li>R-3 — no data loss, no partial writes, no corruption under concurrent access</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-537 T15; EC-03; architecture.md R-3.</p>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"spring.autoconfigure.exclude=", "ebw.tenant-flyway.enabled=false"}
)
@ActiveProfiles("integration")
@Testcontainers
class PrfSaltConcurrencyIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String TENANT        = "prfconcurrency";
    private static final String TENANT_SCHEMA = TENANT + SCHEMA_SUFFIX;

    private static UUID HOLDER_UUID;
    private static String HOLDER_ID;

    private static final String CRED_ID = "cred-concurrent-1";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("prf_concurrency_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/prf_concurrency_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/prf_concurrency_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired PrfSaltService prfSaltService;

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
                    + "VALUES ('" + HOLDER_ID + "', 'concurrent@test.com') "
                    + "ON CONFLICT (id) DO NOTHING");
            conn.createStatement().execute(
                    "DELETE FROM " + TENANT_SCHEMA + ".hybrid_prf_salt");
        }
    }

    // ------------------------------------------------------------------ EC-03

    @Test
    void concurrentInit_sameKey_exactlyOneRowPersisted() throws SQLException {
        // Launch two simultaneous getOrCreatePrfSalt for the same (H1, C1)
        Mono<byte[]> call1 = prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT));
        Mono<byte[]> call2 = prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT));

        // Mono.zip subscribes to both simultaneously
        StepVerifier.create(Mono.zip(call1, call2))
                .assertNext(tuple -> {
                    byte[] salt1 = tuple.getT1();
                    byte[] salt2 = tuple.getT2();
                    assertThat(salt1).hasSize(32);
                    assertThat(salt2).hasSize(32);
                    // Both callers must receive the same salt (EC-03)
                    assertThat(salt1).isEqualTo(salt2);
                })
                .verifyComplete();

        // Verify exactly one row in the DB (no duplicate insert)
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + TENANT_SCHEMA + ".hybrid_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_ID + "' AND credential_id = '" + CRED_ID + "'")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("Concurrent init must produce exactly one DB row (EC-03)")
                    .isEqualTo(1);
        }
    }

    @Test
    void concurrentInit_sameKey_neitherCallPropagatesError() {
        // Neither concurrent call should result in a 500/error signal (R-3)
        Mono<byte[]> call1 = prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT));
        Mono<byte[]> call2 = prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                .contextWrite(ctx -> ctx.put("tenantDomain", TENANT));

        StepVerifier.create(Mono.zip(call1, call2))
                .assertNext(tuple -> {
                    // Both complete successfully — no error propagated
                    assertThat(tuple.getT1()).isNotNull();
                    assertThat(tuple.getT2()).isNotNull();
                })
                .verifyComplete();  // verifyComplete asserts no error signal
    }

    @Test
    void concurrentInit_sameKey_returnedSaltMatchesPersistedSalt() throws SQLException {
        // Capture what both concurrent callers received
        Tuple2<byte[], byte[]> results = Mono.zip(
                prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)),
                prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, CRED_ID)
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
        ).block();

        assertThat(results).isNotNull();
        byte[] returnedSalt = results.getT1();

        // Read the actually persisted salt directly from the DB
        byte[] persistedSalt;
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT prf_salt FROM " + TENANT_SCHEMA + ".hybrid_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_ID + "' AND credential_id = '" + CRED_ID + "'")) {
            assertThat(rs.next()).isTrue();
            persistedSalt = rs.getBytes("prf_salt");
        }

        assertThat(returnedSalt).hasSize(32);
        assertThat(persistedSalt).hasSize(32);
        // The value returned to callers must equal what is stored in the DB
        assertThat(returnedSalt).isEqualTo(persistedSalt);
    }

    @Test
    void concurrentInit_differentCredentials_twoDistinctRows() throws SQLException {
        // Concurrent init for two different credentials of the same holder — should produce
        // two distinct rows with different salts (no interference between concurrent operations)
        String credId1 = "cred-concurrent-diff-1";
        String credId2 = "cred-concurrent-diff-2";

        Tuple2<byte[], byte[]> results = Mono.zip(
                prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, credId1)
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT)),
                prfSaltService.getOrCreatePrfSalt(TENANT, HOLDER_ID, credId2)
                        .contextWrite(ctx -> ctx.put("tenantDomain", TENANT))
        ).block();

        assertThat(results).isNotNull();

        // Two distinct rows with different salts
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test");
             ResultSet rs = conn.createStatement().executeQuery(
                     "SELECT COUNT(*) FROM " + TENANT_SCHEMA + ".hybrid_prf_salt "
                     + "WHERE holder_id = '" + HOLDER_ID + "' "
                     + "AND credential_id IN ('" + credId1 + "', '" + credId2 + "')")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1))
                    .as("Two concurrent inits for different credentials must produce two rows")
                    .isEqualTo(2);
        }

        // The two salts must be distinct
        assertThat(results.getT1()).isNotEqualTo(results.getT2());
    }
}
