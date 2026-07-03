package com.eudistack.ebw.keymanager.infrastructure.health;

import com.eudistack.ebw.keymanager.domain.port.WrappedKeyHandleRepository;
import com.eudistack.ebw.keymanager.infrastructure.observability.HybridKeyManagerTelemetry;
import com.eudistack.ebw.wallet.profile.domain.port.WalletProfileQueryPort;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link HybridHealthContributor} (US-09 / EUDISTACK-541).
 *
 * <p>Hybrid mode is per-tenant ({@code tenant_wallet_profile.key_manager}), so there is no
 * global property gating this bean — it is always registered, exactly like every other
 * hybrid-related bean in {@code KeyManagerConfiguration}.
 *
 * <p>Covered criteria:
 * <ul>
 *   <li>Bean is always registered in the application context (no conditional)</li>
 *   <li>GET /actuator/health includes the {@code hybrid} component</li>
 *   <li>When the requesting tenant cannot be resolved (no seeded {@code tenant_wallet_profile}
 *       row in this fresh Testcontainers DB), the component reports a neutral UP rather than
 *       running the hybrid-only checks</li>
 * </ul>
 */
@Tag("integration")
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "management.endpoint.health.show-details=always",
            "management.endpoint.health.show-components=always"
        }
)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@Testcontainers
class HybridHealthContributorIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("hybrid_health_it")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        String host = postgres.getHost();
        int port    = postgres.getMappedPort(5432);
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + host + ":" + port + "/hybrid_health_it");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () ->
                "jdbc:postgresql://" + host + ":" + port + "/hybrid_health_it");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "public");
        registry.add("management.otlp.tracing.endpoint", () -> "http://localhost:14250");
    }

    @Autowired
    WebTestClient webTestClient;

    // -------------------------------------------------------------------------
    // Actuator endpoint — full Spring Boot context
    // -------------------------------------------------------------------------

    @Test
    void getActuatorHealth_hybridContributor_isPresent_andNeutralForUnresolvedTenant() {
        // This Testcontainers DB has no seeded tenant_wallet_profile rows, so the requesting
        // tenant cannot be resolved to a hybrid profile — the indicator must report a neutral
        // UP rather than running (and failing) the hybrid-only checks.
        webTestClient.get().uri("/health")
                .exchange()
                .expectBody()
                .jsonPath("$.components.hybrid").exists()
                .jsonPath("$.components.hybrid.status").isEqualTo("UP")
                .jsonPath("$.components.hybrid.details.hybrid_applicable").isEqualTo(false);
    }

    // -------------------------------------------------------------------------
    // Bean registration — ApplicationContextRunner (lightweight)
    // -------------------------------------------------------------------------

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
            .withBean(WalletProfileQueryPort.class,
                    () -> Mockito.mock(WalletProfileQueryPort.class))
            .withBean(WrappedKeyHandleRepository.class,
                    () -> Mockito.mock(WrappedKeyHandleRepository.class))
            .withBean(HybridKeyManagerTelemetry.class)
            .withUserConfiguration(HybridHealthContributor.class);

    @Test
    void bean_alwaysRegistered_regardlessOfKeymanagerTypeProperty() {
        // No @ConditionalOnProperty on this bean (unlike the old US-09 draft) — hybrid mode
        // is resolved per-request, per-tenant, not from a deployment-wide property.
        runner.run(ctx -> assertThat(ctx).hasSingleBean(HybridHealthContributor.class));
    }
}
