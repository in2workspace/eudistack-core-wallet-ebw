package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantAwareConnectionFactoryDecorator;
import com.eudistack.ebw.keymanager.domain.model.HolderKey;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring.SpringHolderKeyRepository;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link HolderKeyR2dbcAdapter} using the {@link DataR2dbcTest} slice.
 *
 * <p>Covered criteria (AC-01, AC-02, AC-03 from EUDISTACK-116 acceptance-criteria.md):
 * <ul>
 *   <li>AC-01 — save persists a HolderKey and findByKeyId returns the domain record</li>
 *   <li>AC-02 — findActiveByHolderAndCredential returns the active (non-revoked) key</li>
 *   <li>AC-03 — findActiveByHolderAndCredential propagates Mono.empty() for revoked keys</li>
 * </ul>
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
        HolderKeyR2dbcAdapter holderKeyR2dbcAdapter(SpringHolderKeyRepository repository) {
            return new HolderKeyR2dbcAdapter(repository);
        }
    }

    private static final String SCHEMA_SUFFIX = "_business_wallet";

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

    private HolderKey sampleKey(String keyId, String holderId, String credentialId) {
        return new HolderKey(
                keyId, holderId, credentialId, testTenant,
                new byte[]{1, 2, 3, 4, 5},
                "{\"kty\":\"EC\",\"crv\":\"P-256\"}",
                "ES256",
                CredentialFormat.DC_SD_JWT,
                Instant.now(),
                null
        );
    }

    private <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, testTenant));
    }

    // -------------------------------------------------------------------------
    // AC-01 — save + findByKeyId
    // -------------------------------------------------------------------------

    @Test
    void save_and_findByKeyId_returnsDomainRecord() {
        String keyId = UUID.randomUUID().toString();
        HolderKey key = sampleKey(keyId, "holder-1", "cred-1");

        StepVerifier.create(
                withTenant(adapter.save(key).flatMap(saved -> adapter.findByKeyId(keyId))))
                .assertNext(found -> {
                    assertThat(found.keyId()).isEqualTo(keyId);
                    assertThat(found.holderId()).isEqualTo("holder-1");
                    assertThat(found.credentialId()).isEqualTo("cred-1");
                    assertThat(found.tenantId()).isEqualTo(testTenant);
                    assertThat(found.encryptedPrivateKey()).isEqualTo(new byte[]{1, 2, 3, 4, 5});
                    assertThat(found.algorithm()).isEqualTo("ES256");
                    assertThat(found.format()).isEqualTo(CredentialFormat.DC_SD_JWT);
                    assertThat(found.revokedAt()).isNull();
                    assertThat(found).isInstanceOf(HolderKey.class);
                })
                .verifyComplete();
    }

    @Test
    void findByKeyId_returnsEmpty_whenKeyNotFound() {
        StepVerifier.create(withTenant(adapter.findByKeyId("non-existent-id")))
                .as("findByKeyId must return Mono.empty() when no row matches")
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // AC-02 — findActiveByHolderAndCredential returns active key
    // -------------------------------------------------------------------------

    @Test
    void findActiveByHolderAndCredential_returnsActiveKey() {
        String keyId = UUID.randomUUID().toString();
        HolderKey key = sampleKey(keyId, "holder-2", "cred-2");

        StepVerifier.create(
                withTenant(adapter.save(key)
                        .flatMap(saved -> adapter.findActiveByHolderAndCredential("holder-2", "cred-2"))))
                .assertNext(found -> {
                    assertThat(found.keyId()).isEqualTo(keyId);
                    assertThat(found.isRevoked()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void findActiveByHolderAndCredential_returnsEmpty_whenNotFound() {
        StepVerifier.create(
                withTenant(adapter.findActiveByHolderAndCredential("unknown-holder", "unknown-cred")))
                .as("must propagate Mono.empty() when no active key exists")
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // AC-03 — revoked key is not returned by findActiveByHolderAndCredential
    // -------------------------------------------------------------------------

    @Test
    void findActiveByHolderAndCredential_returnsEmpty_whenKeyIsRevoked() {
        String keyId = UUID.randomUUID().toString();
        Instant revokedAt = Instant.now();
        var revokedKey = new HolderKey(
                keyId, "holder-3", "cred-3", testTenant,
                new byte[]{1, 2, 3},
                "{\"kty\":\"EC\"}",
                "ES256",
                CredentialFormat.DC_SD_JWT,
                revokedAt.minusSeconds(3600),
                revokedAt
        );

        StepVerifier.create(
                withTenant(adapter.save(revokedKey)
                        .flatMap(saved -> adapter.findActiveByHolderAndCredential("holder-3", "cred-3"))))
                .as("revoked key must not be returned by findActiveByHolderAndCredential (AC-03)")
                .verifyComplete();
    }
}