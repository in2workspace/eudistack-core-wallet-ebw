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
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link HolderKeyR2dbcAdapter#findById} (US-03 T8).
 *
 * <p>Covers: EUDISTACK-407 AC-05/F1, AC-06, EC-01, ES-02 — findById with tenant isolation,
 * holder isolation (intra-tenant IDOR), revoked key filter, cross-tenant isolation,
 * and non-existent key.</p>
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
        HolderKeyReadByIdR2dbcIT.AdapterTestConfig.class
})
@Testcontainers
class HolderKeyReadByIdR2dbcIT {

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
                    .withDatabaseName("read_by_id_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://"
                + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/read_by_id_test");
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

    private <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, testTenant));
    }

    private HolderKey insertActiveKey() {
        HolderKey key = new HolderKey(
                HolderKeyId.generate(), testTenant, "holder-A", "cred-A",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                new byte[]{1, 2, 3}, SAMPLE_JWK, Instant.now(), null);
        withTenant(adapter.upsertIfAbsent(key)).block();
        return key;
    }

    // --- AC-06: findById returns the key for the correct tenant/holder/keyId ---

    @Test
    void findById_existingActiveKey_returnsKey() {
        // Given
        HolderKey key = insertActiveKey();

        // When / Then
        StepVerifier.create(withTenant(adapter.findById(testTenant, "holder-A", key.id())))
                .assertNext(found -> {
                    assertThat(found.id()).isEqualTo(key.id());
                    assertThat(found.tenantId()).isEqualTo(testTenant);
                    assertThat(found.holderId()).isEqualTo("holder-A");
                    assertThat(found.revokedAt()).isNull();
                })
                .verifyComplete();
    }

    // --- ES-02: findById returns empty for non-existent keyId ---

    @Test
    void findById_nonExistentKeyId_returnsEmpty() {
        StepVerifier.create(withTenant(adapter.findById(testTenant, "holder-A", HolderKeyId.generate())))
                .as("missing key must produce empty Mono (opaque, AC-06)")
                .verifyComplete();
    }

    // --- EC-01: revoked key is treated as not found ---

    @Test
    void findById_revokedKey_returnsEmpty() {
        // Given — insert a revoked key
        Instant revokedAt = Instant.now();
        HolderKey revokedKey = new HolderKey(
                HolderKeyId.generate(), testTenant, "holder-revoked", "cred-revoked",
                CredentialFormat.SD_JWT_VC, KeyAlgorithm.ES256,
                new byte[]{5, 6, 7}, SAMPLE_JWK, revokedAt.minusSeconds(3600), revokedAt);
        withTenant(adapter.upsertIfAbsent(revokedKey)).block();

        // When / Then — revoked key must be invisible
        StepVerifier.create(withTenant(adapter.findById(testTenant, "holder-revoked", revokedKey.id())))
                .as("revoked key must produce empty Mono (EC-01, ADR-025)")
                .verifyComplete();
    }

    // --- ADR-025: cross-tenant key is invisible ---

    @Test
    void findById_keyOfDifferentTenant_returnsEmpty() {
        // Given — insert key under testTenant
        HolderKey key = insertActiveKey();

        // When — query with a different tenant (cross-tenant attempt)
        String otherTenant = "other-" + UUID.randomUUID().toString().substring(0, 8);
        StepVerifier.create(withTenant(adapter.findById(otherTenant, "holder-A", key.id())))
                .as("cross-tenant key must be invisible (ADR-025)")
                .verifyComplete();
    }

    // --- AC-05 / F1: intra-tenant IDOR — key exists but belongs to a different holder ---

    @Test
    void findById_keyBelongsToOtherHolder_sameTenant_returnsEmpty() {
        // Given — key inserted under "holder-A"
        HolderKey key = insertActiveKey();

        // When — query with a different holderId within the same tenant
        StepVerifier.create(withTenant(adapter.findById(testTenant, "holder-B", key.id())))
                .as("intra-tenant IDOR: key of another holder must be invisible (AC-05/F1)")
                .verifyComplete();
    }
}
