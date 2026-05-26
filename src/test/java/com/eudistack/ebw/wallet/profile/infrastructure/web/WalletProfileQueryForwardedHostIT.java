package com.eudistack.ebw.wallet.profile.infrastructure.web;

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
 * Integration test for EC-05: {@code X-Forwarded-Host} header resolves the correct tenant
 * when {@code ebw.security.trust-forwarded-host=true}.
 *
 * <p>In ALB deployments the original client {@code Host} header is overwritten by the
 * load balancer; the original host is forwarded via {@code X-Forwarded-Host}. When the
 * {@code trust-forwarded-host} property is enabled, the {@code TenantDomainWebFilter}
 * prefers this header for tenant extraction.
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
        registry.add("ebw.encryption.key", () -> "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=");
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
    // EC-05 — X-Forwarded-Host with trust-forwarded-host=true
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_xForwardedHost_resolvesTenantWhenTrustEnabled() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "alb.internal.example.com")          // ALB host (irrelevant)
                .header("X-Forwarded-Host", BROWSER_TENANT + ".eudistack.net") // original host
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    @Test
    void getWalletConfigMetadata_withoutXForwardedHost_usesDirectHostHeader() {
        // Fallback: if X-Forwarded-Host is absent, falls back to Host header
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }
}
