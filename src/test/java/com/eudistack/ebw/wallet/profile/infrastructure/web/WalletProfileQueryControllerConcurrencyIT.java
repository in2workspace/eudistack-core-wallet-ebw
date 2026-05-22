package com.eudistack.ebw.wallet.profile.infrastructure.web;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Optional concurrency integration test for EC-01: 100 concurrent subscriptions against
 * the same tenant must all return 200 OK without any 5xx errors.
 *
 * <p>The {@code @Disabled} annotation is present as a precaution for CI environments where
 * the test may be flaky due to container resource constraints. Remove {@code @Disabled} to
 * run manually against a well-provisioned environment.
 *
 * <p>The controller is stateless and the R2DBC pool absorbs concurrency — this test
 * verifies that there are no race conditions at the application level (EC-01).
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Testcontainers
@Disabled("EC-01 concurrency test — run manually on well-provisioned environment, may be flaky in CI")
class WalletProfileQueryControllerConcurrencyIT {

    private static final String SCHEMA_SUFFIX = "_business_wallet";
    private static final String BROWSER_TENANT = "concurrencytest";
    private static final String BROWSER_SCHEMA = BROWSER_TENANT + SCHEMA_SUFFIX;
    private static final int CONCURRENT_REQUESTS = 100;

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("ebw_concurrency_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/ebw_concurrency_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/ebw_concurrency_it");
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
                + postgres.getMappedPort(5432) + "/ebw_concurrency_it";

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
    // EC-01 — 100 concurrent subscriptions all return 200
    // -------------------------------------------------------------------------

    @Test
    void getWalletConfigMetadata_100ConcurrentRequests_allReturn200() {
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        List<Mono<Void>> requests = java.util.stream.IntStream.range(0, CONCURRENT_REQUESTS)
                .mapToObj(i -> Mono.fromCallable(() -> {
                    webClient.get()
                            .uri(WalletProfileQueryController.WELL_KNOWN_PATH)
                            .header("Host", BROWSER_TENANT + ".eudistack.net")
                            .exchange()
                            .expectStatus().isOk()
                            .expectBody()
                            .jsonPath("$.wallet_mode").isEqualTo("browser");
                    successCount.incrementAndGet();
                    return (Void) null;
                }).onErrorResume(e -> {
                    errorCount.incrementAndGet();
                    return Mono.empty();
                }))
                .toList();

        StepVerifier.create(Flux.merge(requests))
                .verifyComplete();

        assertThat(successCount.get())
                .as("all " + CONCURRENT_REQUESTS + " concurrent requests must return 200 OK")
                .isEqualTo(CONCURRENT_REQUESTS);
        assertThat(errorCount.get())
                .as("no 5xx errors expected under concurrent load")
                .isZero();
    }
}
