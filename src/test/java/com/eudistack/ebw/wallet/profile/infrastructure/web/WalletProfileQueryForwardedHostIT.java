package com.eudistack.ebw.wallet.profile.infrastructure.web;

import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Integration test for tenant resolution when {@code ebw.security.trust-forwarded-host=true}.
 *
 * <p>In ALB deployments the original client {@code Host} header is overwritten by the load
 * balancer. The original host is forwarded via {@code X-Forwarded-Host}; when that header is
 * absent or carries no subdomain, the {@code X-Tenant} header is used as fallback.
 *
 * <p>These tests exercise both {@link WellKnownCanonicalHandler} (Netty routing level,
 * canonical RFC 8615 path) and implicitly verify that the resolution contract documented in
 * {@link com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter} is upheld
 * end-to-end.
 *
 * <p>Covered cases:
 * <ul>
 *   <li>EC-05a — {@code X-Forwarded-Host} subdomain resolves tenant
 *   <li>EC-05b — {@code X-Forwarded-Host} absent, {@code X-Tenant} resolves tenant
 *   <li>EC-05c — {@code X-Forwarded-Host} without subdomain, {@code X-Tenant} fallback
 *   <li>EC-05d — neither header present → 404
 * </ul>
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@TestPropertySource(properties = "ebw.security.trust-forwarded-host=true")
@Testcontainers
class WalletProfileQueryForwardedHostIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BROWSER_TENANT = "forwardedhost";
    private static final String BROWSER_SCHEMA = BROWSER_TENANT + SCHEMA_SUFFIX;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_forwarded_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/ebw_forwarded_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/ebw_forwarded_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired
    private WebTestClient webClient;

    @BeforeEach
    void setUp() throws SQLException {
        String jdbcUrl = "jdbc:postgresql://" + postgres.getHost() + ":"
                + postgres.getMappedPort(5432) + "/ebw_forwarded_it";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + BROWSER_SCHEMA);
        }

        Flyway.configure()
                .dataSource(jdbcUrl, "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(BROWSER_SCHEMA)
                .schemas(BROWSER_SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();

        try (Connection conn = DriverManager.getConnection(jdbcUrl, "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + BROWSER_SCHEMA + ".tenant_wallet_profile "
                    + "WHERE tenant = '" + BROWSER_TENANT + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + BROWSER_SCHEMA + ".tenant_wallet_profile "
                    + "(tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + BROWSER_TENANT + "', 'browser', NULL)"
                    + " ON CONFLICT (tenant) DO NOTHING");
        }
    }

    // -------------------------------------------------------------------------
    // EC-05a — X-Forwarded-Host subdomain resolves tenant
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_xForwardedHostWithSubdomain_resolvesTenant() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "alb.internal.example.com")
                .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    // -------------------------------------------------------------------------
    // EC-05b — X-Forwarded-Host absent, X-Tenant resolves tenant
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_xForwardedHostAbsent_xTenantResolvesTenant() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "alb.internal.example.com")
                .header(TenantDomainWebFilter.HEADER_X_TENANT, BROWSER_TENANT)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    // -------------------------------------------------------------------------
    // EC-05c — X-Forwarded-Host without subdomain falls back to X-Tenant
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_xForwardedHostWithoutSubdomain_xTenantFallback() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header(TenantDomainWebFilter.HEADER_X_FORWARDED_HOST, "alb-internal")   // no dot → no subdomain
                .header(TenantDomainWebFilter.HEADER_X_TENANT, BROWSER_TENANT)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    // -------------------------------------------------------------------------
    // EC-05d — neither header present → 404 (Host is not used as fallback)
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_noTenantHeaders_returns404() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")  // ignored in trust mode
                .exchange()
                .expectStatus().isNotFound();
    }
}
