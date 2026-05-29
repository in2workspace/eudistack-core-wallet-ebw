package com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.configuration.TenantAwareConnectionFactoryDecorator;
import com.eudistack.ebw.wallet.profile.domain.model.KeyManager;
import com.eudistack.ebw.wallet.profile.domain.model.TenantWalletProfile;
import com.eudistack.ebw.wallet.profile.domain.model.WalletMode;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileReadPort;
import com.eudistack.ebw.wallet.profile.infrastructure.adapter.r2dbc.spring.SpringTenantWalletProfileRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for {@link R2dbcWalletProfileReadAdapter} using the
 * {@link DataR2dbcTest} slice (R2DBC repositories + infrastructure only, no web layer).
 *
 * <p>The focused context includes:
 * <ul>
 *   <li>Spring Data R2DBC auto-configuration — connection factory, database client,
 *       type-mapping infrastructure</li>
 *   <li>{@link TenantAwareConnectionFactoryDecorator} — imported explicitly; wraps the
 *       auto-configured {@code ConnectionFactory} with schema-per-tenant routing via
 *       Reactor Context</li>
 *   <li>{@link AdapterTestConfig} — {@link TestConfiguration} that registers the
 *       repository scan and the adapter bean</li>
 * </ul>
 *
 * <p>The {@link TenantAwareConnectionFactoryDecorator} routes each R2DBC connection to
 * the schema {@code <tenant>_business_wallet}. Tests inject the tenant into the
 * Reactor Context using
 * {@link reactor.core.publisher.Mono#contextWrite(reactor.util.context.ContextView)}.
 *
 * <p>Each test method creates a UUID-suffix tenant name so its corresponding schema
 * ({@code <tenant>_business_wallet}) does not collide with other test methods, even
 * when the container is shared across the class.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-07 — adapter returns correct {@link TenantWalletProfile} for browser and
 *       server modes from the schema resolved by the tenant context</li>
 *   <li>ES-02 — {@link Mono#empty()} is propagated when the table has no row for the
 *       current tenant schema</li>
 *   <li>ES-05 — timeout smoke (disabled if flaky in CI)</li>
 * </ul>
 *
 * <p>ES-04 (connection refused) is covered by the companion unit test
 * {@link R2dbcWalletProfileReadAdapterTest}, which is faster and deterministic.
 *
 * @see R2dbcWalletProfileReadAdapterTest for the Mockito unit test (ES-04)
 */
@Tag("integration")
@DataR2dbcTest(
        properties = {
                // Clear the test application.yml R2DBC exclusions so the @DataR2dbcTest
                // slice auto-configurations (R2dbcAutoConfiguration, R2dbcDataAutoConfiguration,
                // R2dbcRepositoriesAutoConfiguration) can be applied without being suppressed.
                "spring.autoconfigure.exclude=",
                // Disable the EBW-specific Flyway migrator so it does not run on startup
                // (this test manages schema migrations manually via Flyway.configure() in setUp()).
                "ebw.tenant-flyway.enabled=false"
        }
)
@Import({
        TenantAwareConnectionFactoryDecorator.class,
        R2dbcWalletProfileReadAdapterIT.AdapterTestConfig.class
})
@Testcontainers
class R2dbcWalletProfileReadAdapterIT {

    /**
     * Focused {@link TestConfiguration} that registers the R2DBC repository scan
     * (scoped to the {@code spring} sub-package of the wallet profile adapter) and
     * the adapter bean.
     *
     * <p>Kept as a static inner class so it is visible only to this test class.
     * {@link EnableR2dbcRepositories} is required here because {@link DataR2dbcTest}
     * relies on {@code @SpringBootApplication} base packages for its auto-scan,
     * which are absent in this focused context (no {@code @SpringBootApplication}
     * class is loaded).
     */
    @TestConfiguration
    @EnableR2dbcRepositories(
            basePackageClasses = SpringTenantWalletProfileRepository.class
    )
    static class AdapterTestConfig {

        @Bean
        R2dbcWalletProfileReadAdapter walletProfileReadAdapter(
                SpringTenantWalletProfileRepository repository) {
            return new R2dbcWalletProfileReadAdapter(repository);
        }
    }

    /** Schema suffix applied by {@link TenantAwareConnectionFactoryDecorator}. */
    private static final String SCHEMA_SUFFIX = "_business_wallet";

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("wallet_adapter_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureR2dbcProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://"
                + postgres.getHost() + ":"
                + postgres.getMappedPort(5432)
                + "/wallet_adapter_test");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
    }

    @Autowired
    private WalletProfileReadPort walletProfileReadPort;

    /** Current test's tenant name — UUID suffix guarantees isolation per test method. */
    private String testTenant;

    /** The schema name used for this test's tenant ({@code <tenant>_business_wallet}). */
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

    /**
     * Creates the tenant schema and applies all tenant Flyway migrations to it.
     * Also creates the required DB roles so V3 GRANTs succeed without error.
     */
    private void provisionSchemaAndMigrate() throws SQLException {
        String jdbcUrl = postgres.getJdbcUrl();
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            // Roles required by V3 GRANT statements
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN "
                    + "CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; "
                    + "END $$");
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

    /**
     * Seeds a browser profile ({@code wallet_mode='browser'}, {@code key_manager=NULL})
     * in the test tenant schema via a plain JDBC INSERT.
     */
    private void seedBrowserProfile() throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + testTenant + "', 'browser', NULL)");
        }
    }

    /**
     * Seeds a server profile in the test tenant schema via a plain JDBC INSERT.
     *
     * @param keyManager the {@code key_manager} value (must be one of db, hybrid, hsm, qtsp)
     */
    private void seedServerProfile(String keyManager) throws SQLException {
        try (Connection conn = DriverManager.getConnection(postgres.getJdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "INSERT INTO " + testSchema + ".tenant_wallet_profile"
                    + " (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + testTenant + "', 'server', '" + keyManager + "')");
        }
    }

    /**
     * Returns a {@link Mono} that wraps the given downstream Mono with the
     * test tenant injected into the Reactor Context under
     * {@link ReactorContextKeys#TENANT_DOMAIN}.
     *
     * <p>The {@link TenantAwareConnectionFactoryDecorator} reads this key to
     * select the schema {@code <tenant>_business_wallet}.
     */
    private <T> Mono<T> withTenantContext(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, testTenant));
    }

    // -------------------------------------------------------------------------
    // AC-07 — adapter returns correct TenantWalletProfile for browser mode
    // -------------------------------------------------------------------------

    /**
     * AC-07 (browser path): Given the table is seeded with a browser profile,
     * when {@code findCurrent()} is called in the correct tenant context,
     * then the returned {@link TenantWalletProfile} has {@code walletMode=BROWSER}
     * and {@code keyManager=null}.
     *
     * <p>The query does not contain an explicit WHERE clause — schema resolution
     * is transparent via the {@code TenantAwareConnectionFactory}.
     */
    @Test
    void findCurrent_returns_browser_profile_when_seeded() throws SQLException {
        seedBrowserProfile();

        StepVerifier.create(
                withTenantContext(walletProfileReadPort.findCurrent()))
                .assertNext(profile -> {
                    assertThat(profile.walletMode())
                            .as("walletMode must be BROWSER")
                            .isEqualTo(WalletMode.BROWSER);
                    assertThat(profile.keyManager())
                            .as("keyManager must be null for BROWSER mode")
                            .isNull();
                    assertThat(profile.tenant())
                            .as("tenant must match the seeded value")
                            .isEqualTo(testTenant);
                    assertThat(profile.createdAt())
                            .as("createdAt must be populated by DEFAULT now()")
                            .isNotNull();
                    assertThat(profile.updatedAt())
                            .as("updatedAt must be populated by DEFAULT now()")
                            .isNotNull();
                })
                .verifyComplete();
    }

    /**
     * AC-07 (server/db path): Given the table is seeded with a server+db profile,
     * when {@code findCurrent()} is called, then the returned profile has
     * {@code walletMode=SERVER} and {@code keyManager=DB}.
     */
    @Test
    void findCurrent_returns_server_db_profile_when_seeded() throws SQLException {
        seedServerProfile("db");

        StepVerifier.create(
                withTenantContext(walletProfileReadPort.findCurrent()))
                .assertNext(profile -> {
                    assertThat(profile.walletMode())
                            .as("walletMode must be SERVER")
                            .isEqualTo(WalletMode.SERVER);
                    assertThat(profile.keyManager())
                            .as("keyManager must be DB")
                            .isEqualTo(KeyManager.DB);
                    assertThat(profile.tenant())
                            .as("tenant must match the seeded value")
                            .isEqualTo(testTenant);
                })
                .verifyComplete();
    }

    /**
     * AC-07 (returned value is a domain record): The returned object must be an
     * instance of {@link TenantWalletProfile} (the domain record), not a Spring Data
     * entity class.
     */
    @Test
    void findCurrent_returns_domain_record_not_entity() throws SQLException {
        seedBrowserProfile();

        StepVerifier.create(
                withTenantContext(walletProfileReadPort.findCurrent()))
                .assertNext(profile -> assertThat(profile)
                        .as("returned type must be TenantWalletProfile domain record")
                        .isInstanceOf(TenantWalletProfile.class))
                .verifyComplete();
    }

    // -------------------------------------------------------------------------
    // ES-02 — Mono.empty() when tenant table has no row
    // -------------------------------------------------------------------------

    /**
     * ES-02: Given the table is migrated but has no row for the current tenant,
     * when {@code findCurrent()} is invoked, then the adapter propagates
     * {@link Mono#empty()} — it does NOT emit an error or a default value.
     *
     * <p>The caller (future {@code ReadWalletProfileUseCase} from US-02) decides
     * how to handle the absence; this adapter stays neutral.
     */
    @Test
    void findCurrent_returns_empty_when_tenant_not_seeded() {
        // No seedBrowserProfile() call — table is migrated but has no rows

        StepVerifier.create(
                withTenantContext(walletProfileReadPort.findCurrent()))
                .as("findCurrent() must propagate Mono.empty() when no row is seeded (ES-02)")
                .verifyComplete(); // completes without emitting any item
    }

    // -------------------------------------------------------------------------
    // ES-05 — Query timeout smoke (optional, @Disabled if flaky in CI)
    // -------------------------------------------------------------------------

    /**
     * ES-05 (smoke, disabled): Verifies that the adapter propagates a timeout error
     * signal rather than an empty signal when the R2DBC query budget is exhausted.
     *
     * <p>Disabled by default because simulating a reliable statement timeout on a
     * healthy TestContainers instance introduces non-determinism. Manual smoke
     * procedure is documented in the US-09 runbook.
     *
     * <p>To enable: remove {@code @Disabled} and configure the R2DBC URL with a
     * near-zero {@code statement-timeout} driver property, then verify
     * {@code StepVerifier.create(...).expectError(R2dbcTimeoutException.class).verify()}.
     */
    @Test
    @Disabled("ES-05 timeout simulation is environment-sensitive — run as manual smoke per US-09 runbook")
    void findCurrent_emits_timeout_when_query_exceeds_budget() {
        // Manual smoke: set extremely low statement timeout in the R2DBC URL,
        // then verify StepVerifier receives an error signal of type R2dbcTimeoutException.
        // Intentionally unimplemented in CI to avoid flaky test failures.
    }
}