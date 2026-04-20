package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.spi.EmailSender;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.containers.PostgreSQLContainer;
import reactor.core.publisher.Mono;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;

/**
 * Base class for integration tests.
 *
 * <p><b>Shared-container pattern (intentional).</b> Instead of the Testcontainers JUnit 5
 * {@code @Testcontainers} / {@code @Container} annotations — which give per-class container
 * lifecycle — this class starts a <em>single</em> PostgreSQL container once per JVM via a
 * static initializer and reuses it across every integration test class in the suite. The
 * container is never explicitly stopped; the Testcontainers Ryuk reaper cleans it up when the
 * JVM exits.
 *
 * <p>Why: Postgres startup takes roughly 5 seconds. Amortizing that cost across the whole
 * integration suite (currently four {@code Credential*} and two auth test classes) keeps the
 * suite fast enough to run on every push without sacrificing isolation, because:
 * <ul>
 *   <li>Each test allocates a distinct user via an email suffix of {@code System.nanoTime()},
 *       so state from one test cannot leak into another via primary-key collisions.</li>
 *   <li>Flyway migrations run once on the first Spring context load and are idempotent
 *       thereafter (CREATE TABLE IF NOT EXISTS semantics at the schema level via the
 *       {@code ebw} namespace).</li>
 *   <li>Every test class extends this base, so they all share the same container instance
 *       and the same Spring context cache — no cross-context container churn.</li>
 * </ul>
 *
 * <p>If future tests require strict per-class DB isolation (e.g. a destructive schema
 * migration test), switch that specific test class back to the {@code @Testcontainers} +
 * {@code @Container} pattern with a per-class static field rather than changing the base.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("integration")
@Tag("integration")
public abstract class IntegrationTestBase {

    static final PostgreSQLContainer<?> postgres;

    static {
        postgres = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("ebw_test")
                .withUsername("test")
                .withPassword("test");
        postgres.start();
    }

    // Base64-encoded 32-byte AES-256 key for testing
    protected static final String TEST_ENCRYPTION_KEY = "01LvWiH/24uNc/Um3GF8n3sFUwtfv8xBmFST4bc56oc=";

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () ->
                "r2dbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432) + "/ebw_test?schema=ebw");
        registry.add("spring.r2dbc.username", () -> "test");
        registry.add("spring.r2dbc.password", () -> "test");
        registry.add("spring.flyway.url", () -> postgres.getJdbcUrl() + "&schema=ebw");
        registry.add("spring.flyway.user", () -> "test");
        registry.add("spring.flyway.password", () -> "test");
        registry.add("spring.flyway.default-schema", () -> "ebw");
        registry.add("ebw.encryption.key", () -> TEST_ENCRYPTION_KEY);
    }

    @Autowired
    protected WebTestClient webClient;

    @MockitoBean
    protected EmailSender emailSender;

    /** Stores the last OTP sent per email address */
    protected final Map<String, String> capturedOtps = new ConcurrentHashMap<>();

    protected void setupEmailCapture() {
        doAnswer(invocation -> {
            String email = invocation.getArgument(0);
            String code = invocation.getArgument(1);
            capturedOtps.put(email, code);
            return Mono.empty();
        }).when(emailSender).sendOtp(anyString(), anyString());
    }

    @SuppressWarnings("unchecked")
    protected String getAccessToken(String email) {
        setupEmailCapture();

        // Register
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        // Verify
        var otp = capturedOtps.get(email);
        var tokens = webClient.post().uri("/api/v1/auth/verify-email")
                .bodyValue(Map.of("email", email, "code", otp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Map.class)
                .returnResult().getResponseBody();

        return (String) tokens.get("accessToken");
    }
}
