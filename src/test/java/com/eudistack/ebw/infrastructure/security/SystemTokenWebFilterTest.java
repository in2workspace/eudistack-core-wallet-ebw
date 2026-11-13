package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.adapter.verifier.VerifierUnavailableException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for {@link SystemTokenWebFilter}: scope, expected issuer and error answers. */
@ExtendWith(MockitoExtension.class)
class SystemTokenWebFilterTest {

    @Mock private SystemTokenVerifier tokenVerifier;

    private SystemTokenWebFilter filter;
    private final AtomicInteger chainCalls = new AtomicInteger();
    private final WebFilterChain chain = exchange -> Mono.fromRunnable(chainCalls::incrementAndGet);

    @BeforeEach
    void setUp() {
        filter = new SystemTokenWebFilter(tokenVerifier, "/verifier", new ObjectMapper(), true);
    }

    private static MockServerWebExchange onboardingTickets() {
        return MockServerWebExchange.from(MockServerHttpRequest
                .post("http://internal:8080/business-wallet/api/v1/onboarding-tickets")
                .contextPath("/business-wallet")
                .header("Authorization", "Bearer system-token")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "sandbox.stg.eudistack.net"));
    }

    private Mono<Void> run(MockServerWebExchange exchange) {
        return filter.filter(exchange, chain).contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, "sandbox"));
    }

    @Test
    void filter_otherRoute_passesThroughWithoutVerifying() {
        // Arrange
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/auth/register"));

        // Act
        StepVerifier.create(run(exchange)).verifyComplete();

        // Assert
        assertThat(chainCalls).hasValue(1);
        verifyNoInteractions(tokenVerifier);
    }

    @Test
    void filter_routeWithPathParameter_isStillVerified() {
        // Arrange: Spring routes ";x=1" to the controller, so the filter must match it too (security F4)
        var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("http://internal:8080/business-wallet/api/v1/onboarding-tickets;x=1")
                .contextPath("/business-wallet")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "sandbox.stg.eudistack.net"));
        when(tokenVerifier.verify(null, "sandbox", "https://sandbox.stg.eudistack.net/verifier"))
                .thenReturn(Mono.error(SystemTokenRejectedException.invalidToken("missing")));

        // Act
        StepVerifier.create(run(exchange)).verifyComplete();

        // Assert
        assertThat(chainCalls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_validToken_storesTheCallerAndContinues() {
        // Arrange
        var exchange = onboardingTickets();
        when(tokenVerifier.verify("system-token", "sandbox", "https://sandbox.stg.eudistack.net/verifier"))
                .thenReturn(Mono.just(new SystemCaller("portal")));

        // Act
        StepVerifier.create(run(exchange)).verifyComplete();

        // Assert
        assertThat(chainCalls).hasValue(1);
        assertThat((SystemCaller) exchange.getAttribute(SystemTokenWebFilter.SYSTEM_CALLER_ATTRIBUTE))
                .isEqualTo(new SystemCaller("portal"));
    }

    @Test
    void filter_rejectedToken_answersItsStatusAndProblem() {
        // Arrange
        var exchange = onboardingTickets();
        when(tokenVerifier.verify(anyString(), any(), anyString()))
                .thenReturn(Mono.error(SystemTokenRejectedException.insufficientPermission("power")));

        // Act
        StepVerifier.create(run(exchange)).verifyComplete();

        // Assert
        assertThat(chainCalls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        StepVerifier.create(exchange.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).contains("\"type\":\"insufficient_permission\""))
                .verifyComplete();
    }

    @Test
    void filter_verifierUnavailable_answers503() {
        // Arrange
        var exchange = onboardingTickets();
        when(tokenVerifier.verify(anyString(), eq("sandbox"), anyString()))
                .thenReturn(Mono.error(new VerifierUnavailableException("down")));

        // Act
        StepVerifier.create(run(exchange)).verifyComplete();

        // Assert
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(chainCalls).hasValue(0);
    }

    @Test
    void publicOrigin_untrustedProxy_usesTheRequestHost() {
        // Arrange
        var untrusted = new SystemTokenWebFilter(tokenVerifier, "/verifier", new ObjectMapper(), false);

        // Act + Assert
        assertThat(untrusted.publicOrigin(onboardingTickets().getRequest())).isEqualTo("http://internal:8080");
    }
}
