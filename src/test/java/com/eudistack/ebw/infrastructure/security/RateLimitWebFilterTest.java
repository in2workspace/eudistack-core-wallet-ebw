package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RateLimitWebFilter} — per-IP budgets on the public auth and hybrid key endpoints, the
 * RFC 7807 429 response written by the filter itself, and client IP resolution.
 */
class RateLimitWebFilterTest {

    // registerPerIp=2, verifyPerIp=2, refreshPerIp=2, logoutPerIp=2, hybridSignPerIp=2, window=1h
    private static final RateLimitProperties PROPERTIES =
            new RateLimitProperties(10, 2, 10, 2, 2, 2, 2, Duration.ofHours(1));

    private RateLimitWebFilter filter;
    private AtomicInteger chainCalls;
    private WebFilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new RateLimitWebFilter(PROPERTIES, new ObjectMapper());
        chainCalls = new AtomicInteger();
        chain = exchange -> Mono.fromRunnable(chainCalls::incrementAndGet);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/auth/register", "/api/v1/auth/verify-email", "/api/v1/auth/refresh", "/api/v1/auth/logout",
            "/api/v1/keys/hybrid/onboarding/init", "/api/v1/keys/hybrid/sign/submit"})
    void filter_limitedEndpointOverBudget_returns429ProblemWithRetryAfter(String path) {
        // Arrange
        StepVerifier.create(filter.filter(post(path, "10.0.0.1"), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post(path, "10.0.0.1"), chain)).verifyComplete();
        var third = post(path, "10.0.0.1");

        // Act
        StepVerifier.create(filter.filter(third, chain)).verifyComplete();

        // Assert
        assertThat(chainCalls).hasValue(2);
        var response = third.getResponse();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getFirst("Retry-After")).isEqualTo("3600");
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        StepVerifier.create(response.getBodyAsString())
                .assertNext(body -> assertThat(body).contains("urn:eudistack:error:rate-limit-exceeded"))
                .verifyComplete();
    }

    @Test
    void filter_hybridEndpoints_shareOneBudgetPerIp() {
        // Arrange
        StepVerifier.create(filter.filter(post("/api/v1/keys/hybrid/onboarding/commit", "10.0.0.2"), chain))
                .verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/keys/hybrid/sign/prepare", "10.0.0.2"), chain))
                .verifyComplete();
        var third = post("/api/v1/keys/hybrid/onboarding/init", "10.0.0.2");

        // Act
        StepVerifier.create(filter.filter(third, chain)).verifyComplete();

        // Assert
        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void filter_budgetsAreTrackedPerClientIp() {
        // Arrange
        StepVerifier.create(filter.filter(post("/api/v1/auth/register", "10.0.0.3"), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/auth/register", "10.0.0.3"), chain)).verifyComplete();
        var otherIp = post("/api/v1/auth/register", "10.0.0.4");

        // Act
        StepVerifier.create(filter.filter(otherIp, chain)).verifyComplete();

        // Assert
        assertThat(otherIp.getResponse().getStatusCode()).isNull();
        assertThat(chainCalls).hasValue(3);
    }

    @Test
    void filter_forwardedForHeader_usesTheFirstAddress() {
        // Arrange
        var request = MockServerHttpRequest.post("/api/v1/auth/logout")
                .header("X-Forwarded-For", " 203.0.113.7 , 10.0.0.1")
                .remoteAddress(new InetSocketAddress("10.0.0.1", 443));
        StepVerifier.create(filter.filter(MockServerWebExchange.from(request), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/auth/logout", "203.0.113.7"), chain)).verifyComplete();
        var third = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/logout")
                .header("X-Forwarded-For", "203.0.113.7"));

        // Act
        StepVerifier.create(filter.filter(third, chain)).verifyComplete();

        // Assert — the three requests were counted against 203.0.113.7
        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void filter_noRemoteAddress_countsUnderUnknown() {
        // Arrange
        var noAddress = MockServerHttpRequest.post("/api/v1/auth/refresh");
        StepVerifier.create(filter.filter(MockServerWebExchange.from(noAddress), chain)).verifyComplete();
        StepVerifier.create(filter.filter(MockServerWebExchange.from(noAddress), chain)).verifyComplete();
        var third = MockServerWebExchange.from(noAddress);

        // Act
        StepVerifier.create(filter.filter(third, chain)).verifyComplete();

        // Assert
        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void filter_getRequestsAndUnlimitedPaths_areNeverCounted() {
        // Act
        for (int i = 0; i < 5; i++) {
            StepVerifier.create(filter.filter(MockServerWebExchange.from(
                    MockServerHttpRequest.get("/api/v1/auth/register")), chain)).verifyComplete();
            StepVerifier.create(filter.filter(post("/api/v1/credentials", "10.0.0.5"), chain)).verifyComplete();
        }

        // Assert
        assertThat(chainCalls).hasValue(10);
    }

    @Test
    void getOrder_runsRightAfterTheHighestPrecedenceFilters() {
        // Act + Assert
        assertThat(filter.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 1);
    }

    private static MockServerWebExchange post(String path, String ip) {
        return MockServerWebExchange.from(MockServerHttpRequest.post(path)
                .remoteAddress(new InetSocketAddress(ip, 443)));
    }
}
