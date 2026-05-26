package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantAwareConnectionFactoryDecorator;
import com.eudistack.ebw.keymanager.domain.model.CredentialFormat;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyPersistResult;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link HolderKeyR2dbcAdapter} using the {@link DataR2dbcTest} slice.
 *
 * <p>Covered criteria (from EUDISTACK-119 acceptance-criteria.md):
 * <ul>
 *   <li>AC-04 — upsertIfAbsent persists a HolderKey and findBy returns the domain record</li>
 *   <li>AC-05 — findBy returns the active (non-revoked) key for a composite key tuple</li>
 *   <li>AC-05 — findBy propagates Mono.empty() for revoked or absent keys</li>
 * </ul>
 *
 * <p>Note: full UPSERT-ON-CONFLICT idempotency (EC-01, EC-02) and DbUnavailableHandling tests
 * will be implemented in T11.</p>
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
        HolderKeyR2dbcAdapterIT.AdapterTestConfig.class
})
@Testcontainers
class HolderKeyR2dbcAdapterIT {

    @TestConfiguration
    @EnableR2dbcRepositories(basePackageClasses = SpringHolderKeyRepository.class)
    static class AdapterTestConfig {

        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        HolderKeyR2dbcAdapter holderKeyR2dbcAdapter(SpringHolderKeyRepository repository,
                ObjectMapper objectMapper) {
            return new HolderKeyR2dbcAdapter(repository, objectMapper);
        }
    }

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final JwkPublic SAMPLE_JWK = new JwkPublic(
            Map.of("kty", "EC", "crv", "P-256", "x", "sampleX", "y", "sampleY"));

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("holder_key_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureR2dbcProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://"
                + postgres.getHost() + ":"
                + postgres.getMappedPort(5432)
                + "/holder_key_test");
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

    private HolderKey sampleKey(String holderId, String credentialId) {
        return new HolderKey(
                HolderKeyId.generate(),
                testTenant,
                holderId,
                credentialId,
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                new byte[]{1, 2, 3, 4, 5},
                SAMPLE_JWK,
                Instant.now(),
                null
        );
    }

    private <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, testTenant));
    }

    // -------------------------------------------------------------------------
    // AC-04 — upsertIfAbsent + findBy
    // -------------------------------------------------------------------------

    @Test
    void upsertIfAbsent_and_findBy_returnsDomainRecord() {
        HolderKey key = sampleKey("holder-1", "cred-1");

        StepVerifier.create(
                withTenant(adapter.upsertIfAbsent(key)
                        .map(HolderKeyPersistResult::holderKey)
                        .flatMap(saved -> adapter.findBy(testTenant, "holder-1", "cred-1"))))
                .assertNext(found -> {
                    assertThat(found.holderId()).isEqualTo("holder-1");
                    assertThat(found.credentialId()).isEqualTo("cred-1");
                    assertThat(found.tenantId()).isEqualTo(testTenant);
                    assertThat(found.privateKey()).isEqualTo(new byte[]{1, 2, 3, 4, 5});
                    assertThat(found.algorithm()).isEqualTo(KeyAlgorithm.ES256);
                    assertThat(found.format()).isEqualTo(CredentialFormat.SD_JWT_VC);
                    assertThat(found.revokedAt()).isNull();
                    assertThat(found).isInstanceOf(HolderKey.class);
                })
                .verifyComplete();
    }

    @Test
    void findBy_returnsEmpty_whenKeyNotFound() {
        StepVerifier.create(
                withTenant(adapter.findBy(testTenant, "unknown-holder", "unknown-cred")))
                .as("findBy must return Mono.empty() when no row matches")
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // AC-05 — findBy returns active key for composite key tuple
    // -------------------------------------------------------------------------

    @Test
    void findBy_returnsActiveKey() {
        HolderKey key = sampleKey("holder-2", "cred-2");

        StepVerifier.create(
                withTenant(adapter.upsertIfAbsent(key)
                        .flatMap(result -> adapter.findBy(testTenant, "holder-2", "cred-2"))))
                .assertNext(found -> {
                    assertThat(found.holderId()).isEqualTo("holder-2");
                    assertThat(found.isRevoked()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void findBy_returnsEmpty_whenNotFound() {
        StepVerifier.create(
                withTenant(adapter.findBy(testTenant, "unknown-holder", "unknown-cred")))
                .as("must propagate Mono.empty() when no active key exists")
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // AC-05 — revoked key is not returned
    // -------------------------------------------------------------------------

    @Test
    void findBy_returnsEmpty_whenKeyIsRevoked() {
        Instant revokedAt = Instant.now();
        var revokedKey = new HolderKey(
                HolderKeyId.generate(),
                testTenant,
                "holder-3",
                "cred-3",
                CredentialFormat.SD_JWT_VC,
                KeyAlgorithm.ES256,
                new byte[]{1, 2, 3},
                SAMPLE_JWK,
                revokedAt.minusSeconds(3600),
                revokedAt
        );

        StepVerifier.create(
                withTenant(adapter.upsertIfAbsent(revokedKey)
                        .flatMap(result -> adapter.findBy(testTenant, "holder-3", "cred-3"))))
                .as("revoked key must not be returned by findBy (AC-05)")
                .verifyComplete();
    }
}
