package com.eudistack.ebw.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * AC-06 / NFR-S-103-02: register/OTP requests are rate-limited by email
 * ({@code CaffeineEmailRateLimiter}) AND by origin ({@code RateLimitWebFilter}) —
 * two independent layers (AD-2). Thresholds are lowered via {@code @TestPropertySource}
 * so both limits can be exercised deterministically; this forces a dedicated Spring
 * context for this class, isolated from the shared-context suite (see
 * {@link IntegrationTestBase} javadoc and risk R-4 in technical-design.md).
 */
@TestPropertySource(properties = {
        "ebw.rate-limit.register-per-email=2",
        "ebw.rate-limit.register-per-ip=5"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class RegisterRateLimitIT extends IntegrationTestBase {

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        capturedOtps.clear();
    }

    @Test
    void register_exceedsPerEmailLimit_returns429_andSendsNoFurtherOtp() {
        var email = "rate-limit-email-" + System.nanoTime() + "@example.com";

        // First two requests are within the limit (register-per-email=2)
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isOk();

        // Third request breaches the per-email limit
        webClient.post().uri("/api/v1/auth/register")
                .bodyValue(Map.of("email", email))
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().exists("Retry-After")
                .expectBody()
                .jsonPath("$.type").isEqualTo("urn:eudistack:error:rate-limit-exceeded");

        verify(emailSender, times(2)).sendOtp(eq(email), anyString());
    }

    @Test
    void register_exceedsPerOriginLimit_returns429_regardlessOfEmail() {
        var origin = "203.0.113.7";

        for (int i = 0; i < 5; i++) {
            webClient.post().uri("/api/v1/auth/register")
                    .header("X-Forwarded-For", origin)
                    .bodyValue(Map.of("email", "rate-limit-origin-" + i + "-" + System.nanoTime() + "@example.com"))
                    .exchange()
                    .expectStatus().isOk();
        }

        // Sixth request from the same origin (register-per-ip=5), a brand new email
        webClient.post().uri("/api/v1/auth/register")
                .header("X-Forwarded-For", origin)
                .bodyValue(Map.of("email", "rate-limit-origin-6-" + System.nanoTime() + "@example.com"))
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().exists("Retry-After");
    }
}
