package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantAwareConnectionFactoryDecorator;
import com.eudistack.ebw.keymanager.domain.model.HolderKeyId;
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
import java.util.UUID;

/**
 * Integration tests verifying ES-04 for the signing read path:
 * when the holder_key table is unavailable, {@link HolderKeyR2dbcAdapter#findById} propagates
 * a reactive error signal.
 *
 * <p>Covers: EUDISTACK-407 ES-04 (dependency failure), AC-06.</p>
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
        SignDbUnavailableHandlingIT.AdapterTestConfig.class
})
@Testcontainers
class SignDbUnavailableHandlingIT {

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

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("sign_db_unavail_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://"
                + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/sign_db_unavail_test");
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

    // --- ES-04: findById propagates error when holder_key table does not exist ---

    @Test
    void findById_holderKeyTableDropped_propagatesReactiveError() throws SQLException {
        // Given — drop the holder_key table to simulate DB schema unavailability
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute("DROP TABLE IF EXISTS " + testSchema + ".holder_key CASCADE");
        }

        // When / Then — must propagate a reactive error, not silently return empty
        StepVerifier.create(withTenant(adapter.findById(testTenant, "any-holder", HolderKeyId.generate())))
                .expectError()
                .verify();
    }
}
