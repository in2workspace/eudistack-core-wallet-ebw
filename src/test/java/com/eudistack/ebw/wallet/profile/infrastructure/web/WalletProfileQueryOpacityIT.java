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
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test verifying byte-exact equality of the three 404 opaque paths
 * (NFR-S-413-01, AD-413-2).
 *
 * <p>The three paths that must produce identical body + headers are:
 * <ol>
 *   <li>AC-04 — host not registered: no schema exists for the resolved tenant.
 *   <li>AC-05 — tenant existing without profile: schema exists but table is empty.
 *   <li>AC-08 — host malformed: {@code TenantDomainWebFilter} cannot extract tenant.
 * </ol>
 *
 * <p>Byte-exact equality is enforced by {@link WalletProfileQueryExceptionHandler#buildOpaque404Response()}
 * being the single construction point. This test detects any future drift.
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
class WalletProfileQueryOpacityIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String SEEDED_NO_PROFILE_TENANT = "noprofileopacity";
    private static final String SEEDED_NO_PROFILE_SCHEMA = SEEDED_NO_PROFILE_TENANT + SCHEMA_SUFFIX;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_opacity_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/ebw_opacity_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/ebw_opacity_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
    }

    @Autowired
    private WebTestClient webClient;

    @BeforeEach
    void setUp() throws SQLException {
        // Provision a tenant schema but DO NOT seed a profile row — this is the AC-05 path
        try (Connection conn = DriverManager.getConnection(jdbcUrl(), "test", "test")) {
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE ebw_app_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "DO $$ BEGIN CREATE ROLE config_manager_role; "
                    + "EXCEPTION WHEN duplicate_object THEN NULL; END $$");
            conn.createStatement().execute(
                    "CREATE SCHEMA IF NOT EXISTS " + SEEDED_NO_PROFILE_SCHEMA);
        }
        Flyway.configure()
                .dataSource(jdbcUrl(), "test", "test")
                .locations("classpath:db/tenant")
                .defaultSchema(SEEDED_NO_PROFILE_SCHEMA)
                .schemas(SEEDED_NO_PROFILE_SCHEMA)
                .table("flyway_schema_history")
                .baselineOnMigrate(true)
                .load()
                .migrate();
    }

    private String jdbcUrl() {
        return "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432)
                + "/ebw_opacity_it";
    }

    /**
     * NFR-S-413-01: the response body for all three 404 paths must be byte-exactly equal.
     *
     * <p>Also verifies that the three paths produce identical header sets.
     */
    @Test
    void allThree404Paths_produceBytExactEqualBodyAndHeaders() {
        // AC-04: host not registered — no schema exists for this tenant
        byte[] body404HostUnregistered = webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "completelyunknown999.eudistack.net")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectBody()
                .returnResult().getResponseBody();

        // AC-05: tenant schema exists but no profile row — port returns Mono.empty()
        byte[] body404TenantNoProfile = webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", SEEDED_NO_PROFILE_TENANT + ".eudistack.net")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectBody()
                .returnResult().getResponseBody();

        // AC-08: malformed host — TenantDomainWebFilter returns null, no TENANT_DOMAIN in context
        byte[] body404MalformedHost = webClient.get()
                .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                .header("Host", "nodotatall")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().valueEquals("Cache-Control", "public, max-age=60, must-revalidate")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("Referrer-Policy", "no-referrer")
                .expectBody()
                .returnResult().getResponseBody();

        // Byte-exact equality across all three paths (NFR-S-413-01)
        assertThat(body404TenantNoProfile)
                .as("AC-05 body must be byte-exactly equal to AC-04 body (anti-enumeration)")
                .isEqualTo(body404HostUnregistered);

        assertThat(body404MalformedHost)
                .as("AC-08 body must be byte-exactly equal to AC-04 body (anti-enumeration)")
                .isEqualTo(body404HostUnregistered);
    }
}
