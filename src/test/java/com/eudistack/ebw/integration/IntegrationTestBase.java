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
