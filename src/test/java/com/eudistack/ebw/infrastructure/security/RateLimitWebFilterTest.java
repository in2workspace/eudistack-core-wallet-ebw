package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.support.InMemoryIpRateLimiter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RateLimitWebFilter} — per-IP budgets on the public auth and passkey-prf key endpoints, the
 * RFC 7807 429 response written by the filter itself, and client IP resolution.
 */
class RateLimitWebFilterTest {

    // registerPerIp=2, verifyPerIp=2, refreshPerIp=2, passkeyRegistrationPerIp=2, sessionPerIp=2,
    // passkeyPrfSignPerIp=2, trustedProxies=2 (CloudFront + ALB), window=1h
    private static final RateLimitProperties PROPERTIES =
            new RateLimitProperties(10, 2, 10, 2, 2, 2, 2, 2, 2, Duration.ofHours(1));

    private RateLimitWebFilter filter;
    private AtomicInteger chainCalls;
    private WebFilterChain chain;

    @BeforeEach
    void setUp() {
        filter = new RateLimitWebFilter(PROPERTIES, new ObjectMapper(),
                new InMemoryIpRateLimiter(PROPERTIES.window()), new ClientIpResolver(PROPERTIES));
        chainCalls = new AtomicInteger();
        chain = exchange -> Mono.fromRunnable(chainCalls::incrementAndGet);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/v1/auth/register", "/api/v1/auth/verify-email", "/api/v1/auth/refresh",
            "/api/v1/auth/passkeys/registration/options", "/api/v1/auth/passkeys/registration",
            "/api/v1/auth/sessions/options", "/api/v1/auth/sessions"})
    void filter_authEndpointOverBudget_returnsRateLimitedProblemWithRetryAfter(String path) {
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
                .assertNext(body -> assertThat(body).contains("\"type\":\"rate_limited\""))
                .verifyComplete();
    }

    @Test
    void filter_signInOptionsAndSession_shareOneBudgetPerIp() {
        // Arrange
        StepVerifier.create(filter.filter(post("/api/v1/auth/sessions/options", "10.0.0.9"), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/auth/sessions", "10.0.0.9"), chain)).verifyComplete();
        var third = post("/api/v1/auth/sessions/options", "10.0.0.9");

        // Act
        StepVerifier.create(filter.filter(third, chain)).verifyComplete();

        // Assert
        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/v1/keys/passkey-prf/onboarding/init", "/api/v1/keys/passkey-prf/sign/submit"})
    void filter_keyManagerEndpointOverBudget_keepsItsProblemType(String path) {
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
    void filter_passkeyPrfEndpoints_shareOneBudgetPerIp() {
        // Arrange
        StepVerifier.create(filter.filter(post("/api/v1/keys/passkey-prf/onboarding/commit", "10.0.0.2"), chain))
                .verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/keys/passkey-prf/sign/prepare", "10.0.0.2"), chain))
                .verifyComplete();
        var third = post("/api/v1/keys/passkey-prf/onboarding/init", "10.0.0.2");

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

    @Nested
    @DisplayName("Behind the base-path and the trusted proxies")
    class BehindTheProxies {

        @Test
        void filter_requestUnderTheBasePath_isCountedAgainstTheRouteBudget() {
            // Arrange
            StepVerifier.create(filter.filter(underBasePath("/api/v1/auth/register", "10.0.0.6"), chain))
                    .verifyComplete();
            StepVerifier.create(filter.filter(underBasePath("/api/v1/auth/register", "10.0.0.6"), chain))
                    .verifyComplete();
            var third = underBasePath("/api/v1/auth/register", "10.0.0.6");

            // Act
            StepVerifier.create(filter.filter(third, chain)).verifyComplete();

            // Assert
            assertThat(chainCalls).hasValue(2);
            assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        @Test
        void filter_forwardedForWithSpoofedFirstValue_stillCountsTheAddressOurProxiesAppended() {
            // Arrange
            StepVerifier.create(filter.filter(forwarded("198.51.100.1, 203.0.113.7, 10.0.0.1"), chain))
                    .verifyComplete();
            StepVerifier.create(filter.filter(forwarded("198.51.100.2, 203.0.113.7, 10.0.0.1"), chain))
                    .verifyComplete();
            var third = forwarded("198.51.100.3, 203.0.113.7, 10.0.0.1");

            // Act
            StepVerifier.create(filter.filter(third, chain)).verifyComplete();

            // Assert
            assertThat(chainCalls).hasValue(2);
            assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        private MockServerWebExchange underBasePath(String path, String ip) {
            return MockServerWebExchange.from(MockServerHttpRequest.post("/business-wallet" + path)
                    .contextPath("/business-wallet")
                    .remoteAddress(new InetSocketAddress(ip, 443)));
        }

        private MockServerWebExchange forwarded(String forwardedFor) {
            return MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/register")
                    .header("X-Forwarded-For", forwardedFor)
                    .remoteAddress(new InetSocketAddress("10.0.0.1", 443)));
        }
    }

    @Nested
    @DisplayName("Route matching as Spring does it")
    class RouteMatching {

        @ParameterizedTest
        @ValueSource(strings = {"/api/v1/auth/register;x=1", "/api/v1/auth/regist%65r"})
        void filter_variantOfALimitedRoute_isCountedAgainstTheSameBudget(String variant) {
            // Arrange
            StepVerifier.create(filter.filter(rawPost("/api/v1/auth/register", "10.0.0.7"), chain)).verifyComplete();
            StepVerifier.create(filter.filter(rawPost(variant, "10.0.0.7"), chain)).verifyComplete();
            var third = rawPost("/api/v1/auth/register", "10.0.0.7");

            // Act
            StepVerifier.create(filter.filter(third, chain)).verifyComplete();

            // Assert
            assertThat(chainCalls).hasValue(2);
            assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        @Test
        void filter_variantsOnly_neverSkipTheLimit() {
            // Arrange
            StepVerifier.create(filter.filter(rawPost("/api/v1/auth/register;a=1", "10.0.0.8"), chain))
                    .verifyComplete();
            StepVerifier.create(filter.filter(rawPost("/api/v1/auth/register;a=2", "10.0.0.8"), chain))
                    .verifyComplete();
            var third = rawPost("/api/v1/auth/register;a=3", "10.0.0.8");

            // Act
            StepVerifier.create(filter.filter(third, chain)).verifyComplete();

            // Assert
            assertThat(chainCalls).hasValue(2);
            assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        private MockServerWebExchange rawPost(String rawPath, String ip) {
            return MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.POST, URI.create(rawPath))
                    .remoteAddress(new InetSocketAddress(ip, 443)));
        }
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
