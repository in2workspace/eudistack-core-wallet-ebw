package com.eudistack.ebw.integration;

import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Map;

/**
 * EUD-310: the per-IP limits must hold behind the {@code /business-wallet} base-path and behind the CloudFront +
 * ALB chain. The client below sends every request with the prefix and an {@code X-Forwarded-For} shaped like the
 * one the infrastructure builds: whatever the client wrote, then its address, then the CloudFront edge.
 */
@TestPropertySource(properties = {
        "spring.webflux.base-path=/business-wallet",
        "ebw.rate-limit.register-per-ip=2",
        "ebw.rate-limit.verify-per-ip=2",
        "ebw.rate-limit.refresh-per-ip=2",
        "ebw.rate-limit.passkey-registration-per-ip=2",
        "ebw.rate-limit.session-per-ip=2",
        "ebw.rate-limit.passkey-prf-sign-per-ip=2",
        "ebw.rate-limit.trusted-proxies=2"
})
class RateLimitBasePathIT extends IntegrationTestBase {

    private static final String REGISTER = "/api/v1/auth/register";

    @LocalServerPort
    private int port;

    private WebTestClient prefixedClient;

    @BeforeEach
    void setUp() {
        setupEmailCapture();
        prefixedClient = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port + "/business-wallet")
                .defaultHeader(TenantDomainWebFilter.HEADER_X_TENANT, TEST_TENANT)
                .build();
    }

    @Test
    void register_overThePerIpLimitUnderTheBasePath_returns429() {
        // Arrange
        var forwardedFor = "198.51.100.1, 203.0.113.50, 10.0.0.9";
        register(forwardedFor).expectStatus().isAccepted();
        register(forwardedFor).expectStatus().isAccepted();

        // Act
        var third = register(forwardedFor);

        // Assert
        third.expectStatus().isEqualTo(429).expectHeader().exists("Retry-After");
    }

    @Test
    void register_clientChangesTheFirstForwardedForValue_doesNotSkipTheLimit() {
        // Arrange
        register("198.51.100.1, 203.0.113.51, 10.0.0.9").expectStatus().isAccepted();
        register("198.51.100.2, 203.0.113.51, 10.0.0.9").expectStatus().isAccepted();

        // Act
        var third = register("198.51.100.3, 203.0.113.51, 10.0.0.9");

        // Assert
        third.expectStatus().isEqualTo(429);
    }

    @Test
    void register_anotherClientAddress_isNotAffectedByTheExhaustedOne() {
        // Arrange
        register("198.51.100.1, 203.0.113.52, 10.0.0.9").expectStatus().isAccepted();
        register("198.51.100.1, 203.0.113.52, 10.0.0.9").expectStatus().isAccepted();
        register("198.51.100.1, 203.0.113.52, 10.0.0.9").expectStatus().isEqualTo(429);

        // Act
        var otherClient = register("198.51.100.1, 203.0.113.53, 10.0.0.9");

        // Assert
        otherClient.expectStatus().isAccepted();
    }

    @ParameterizedTest
    @CsvSource({
            "/api/v1/auth/verify-email, rate_limited, 203.0.113.60",
            "/api/v1/auth/refresh, rate_limited, 203.0.113.61",
            "/api/v1/auth/passkeys/registration/options, rate_limited, 203.0.113.62",
            "/api/v1/auth/passkeys/registration, rate_limited, 203.0.113.63",
            "/api/v1/auth/sessions/options, rate_limited, 203.0.113.64",
            "/api/v1/auth/sessions, rate_limited, 203.0.113.65",
            "/api/v1/keys/passkey-prf/onboarding/init, urn:eudistack:error:rate-limit-exceeded, 203.0.113.66",
            "/api/v1/keys/passkey-prf/sign/submit, urn:eudistack:error:rate-limit-exceeded, 203.0.113.67"})
    void post_overTheGroupLimitUnderTheBasePath_returns429WithTheGroupProblemType(
            String route, String problemType, String clientAddress) {
        // Arrange
        var forwardedFor = "198.51.100.1, " + clientAddress + ", 10.0.0.9";
        post(route, forwardedFor).expectBody().returnResult();
        post(route, forwardedFor).expectBody().returnResult();

        // Act
        var third = post(route, forwardedFor);

        // Assert
        third.expectStatus().isEqualTo(429)
                .expectHeader().exists("Retry-After")
                .expectBody().jsonPath("$.type").isEqualTo(problemType);
    }

    private WebTestClient.ResponseSpec post(String route, String forwardedFor) {
        return prefixedClient.post().uri(route)
                .header("X-Forwarded-For", forwardedFor)
                .bodyValue(Map.of())
                .exchange();
    }

    private WebTestClient.ResponseSpec register(String forwardedFor) {
        return prefixedClient.post().uri(REGISTER)
                .header("X-Forwarded-For", forwardedFor)
                .bodyValue(Map.of("email", "base-path-" + System.nanoTime() + "@example.com"))
                .exchange();
    }
}
