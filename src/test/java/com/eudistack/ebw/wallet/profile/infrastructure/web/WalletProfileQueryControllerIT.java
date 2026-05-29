package com.eudistack.ebw.wallet.profile.infrastructure.web;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Integration tests for {@link WalletProfileQueryController} using the full Spring Boot
 * context with a real PostgreSQL container.
 *
 * <p>The {@code TenantDomainWebFilter} resolves the tenant from the request {@code Host}
 * header. Tests send {@code Host: <tenant>.eudistack.net} to trigger tenant resolution.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>AC-01 — browser mode returns 200 + JSON with {@code wallet_mode="browser"}
 *   <li>AC-02 — server mode + each key_manager returns 200 + correct JSON
 *   <li>AC-03 — no Authorization header required
 *   <li>AC-06 — security headers present on 200 and 404
 *   <li>AC-08 — malformed host → 404 (not 400)
 *   <li>EC-02 — host with explicit port resolves tenant correctly
 *   <li>EC-03 — uppercase host is normalised to lowercase
 *   <li>EC-04 — HEAD method returns headers without body
 *   <li>ES-01 — host with invalid syntax → 404 (not 400)
 *   <li>registered_outside_business_wallet_prefix — GET /business-wallet/.well-known/... → 404
 *   <li>NFR-S-413-03 — security headers present on all responses
 * </ul>
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class WalletProfileQueryControllerIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BROWSER_TENANT = "sandboxbrowser";
    private static final String BROWSER_SCHEMA = BROWSER_TENANT + SCHEMA_SUFFIX;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_controller_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/ebw_controller_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/ebw_controller_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("ebw.encryption.key", () -> "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=");
    }

    @Autowired
    private WebTestClient webClient;

    @BeforeEach
    void setUp() throws SQLException {
        provisionTenantSchema(BROWSER_TENANT, BROWSER_SCHEMA);
        seedBrowserProfile(BROWSER_TENANT, BROWSER_SCHEMA);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String jdbcUrl() {
        return "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/ebw_controller_it";
    }

    private void provisionTenantSchema(String tenant, String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute("CREATE SCHEMA IF NOT EXISTS " + schema);
        }
        Flyway.configure()
                .dataSource(jdbcUrl(), "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private void seedBrowserProfile(String tenant, String schema) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".tenant_wallet_profile WHERE tenant = '" + tenant + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + tenant + "', 'browser', NULL)"
                    + " ON CONFLICT (tenant) DO NOTHING");
        }
    }

    private void seedServerProfile(String tenant, String schema, String keyManager) throws SQLException {
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DELETE FROM " + schema + ".tenant_wallet_profile WHERE tenant = '" + tenant + "'");
            conn.createStatement().execute(
                    "INSERT INTO " + schema + ".tenant_wallet_profile (tenant, wallet_mode, key_manager)"
                    + " VALUES ('" + tenant + "', 'server', '" + keyManager + "')"
                    + " ON CONFLICT (tenant) DO NOTHING");
        }
    }

    // -------------------------------------------------------------------------
    // AC-01 — browser mode returns 200 + correct JSON
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_browserTenant_returns200WithBrowserJson() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser")
                .jsonPath("$.key_manager").doesNotExist();
    }

    // -------------------------------------------------------------------------
    // AC-02 — server mode + each key_manager returns 200 + correct JSON
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"db", "hybrid", "hsm", "qtsp"})
    void getWalletConfigMetadata_serverTenantWithKeyManager_returns200(String keyManager)
            throws SQLException {
        String tenant = "srv" + keyManager;
        String schema = tenant + SCHEMA_SUFFIX;
        provisionTenantSchema(tenant, schema);
        seedServerProfile(tenant, schema, keyManager);

        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", tenant + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("server")
                .jsonPath("$.key_manager").isEqualTo(keyManager);
    }

    // -------------------------------------------------------------------------
    // AC-03 — no Authorization header required
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_noAuthorizationHeader_returns200() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                // Intentionally no Authorization header
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("WWW-Authenticate");
    }

    // -------------------------------------------------------------------------
    // AC-06 + NFR-S-413-03 — security headers present on 200 and 404
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_success_includesAllSecurityHeaders() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
    }

    @Test
    void getWalletConfigMetadata_notFound_includesAllSecurityHeaders() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "unknowntenant999.eudistack.net")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer");
    }

    // -------------------------------------------------------------------------
    // AC-08 + ES-01 — malformed host → 404 (not 400)
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "notadothost",            // no dot — tenant extraction fails
        "just-a-hostname",        // no dot — TenantDomainWebFilter returns null
        "  ",                     // blank
        "-invalid.eudistack.net", // leading hyphen fails regex
        "!bad@host.example.com"   // special chars fail regex
    })
    void getWalletConfigMetadata_malformedHost_returns404NotBadRequest(String host) {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", host)
                .exchange()
                .expectStatus().isNotFound()
                .expectBody()
                .jsonPath("$.error").isEqualTo("tenant_unknown");
    }

    // -------------------------------------------------------------------------
    // EC-02 — host with explicit port resolves tenant correctly
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_hostWithPort_resolvesCorrectTenant() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net:8080")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    // -------------------------------------------------------------------------
    // EC-03 — uppercase host is normalised to lowercase
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_uppercaseHost_normalisedToLowercase() {
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT.toUpperCase() + ".EUDISTACK.NET")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.wallet_mode").isEqualTo("browser");
    }

    // -------------------------------------------------------------------------
    // EC-04 — HEAD method returns headers without body
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_headMethod_returnsHeadersWithoutBody() {
        webClient.method(HttpMethod.HEAD)
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectBody().isEmpty();
    }

    // -------------------------------------------------------------------------
    // registered_outside_business_wallet_prefix — R-413-1 verification
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_registeredOutsideBusinessWalletPrefix() {
        // The canonical path must be accessible
        webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isOk();

        // The prefixed path must return 404 — it is NOT under /business-wallet
        webClient.get()
                .uri("/business-wallet" + WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", BROWSER_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isNotFound();
    }
}
