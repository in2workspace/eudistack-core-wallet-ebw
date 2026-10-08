package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link JwtAuthenticationWebFilter} — a valid Bearer token populates the reactive security
 * context (user id, email, PBAC powers); a missing or invalid token lets the request continue unauthenticated so
 * {@code SecurityConfig} decides (401 on protected routes).
 */
class JwtAuthenticationWebFilterTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private TokenSigner tokenSigner;
    private JwtAuthenticationWebFilter filter;
    private AtomicReference<JwtAuthenticationToken> seenAuthentication;
    private WebFilterChain chain;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        filter = new JwtAuthenticationWebFilter(tokenSigner);
        seenAuthentication = new AtomicReference<>();
        chain = exchange -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .doOnNext(auth -> seenAuthentication.set((JwtAuthenticationToken) auth))
                .then();
    }

    @Test
    void filter_validBearerToken_authenticatesTheRequestWithItsPowers() {
        // Arrange
        var claims = new HashMap<String, Object>();
        claims.put("sub", USER_ID.toString());
        claims.put("email", "holder@example.com");
        claims.put("powers", List.of("Onboarding:Execute", 42, "Certification:Upload"));
        when(tokenSigner.verify("good-token")).thenReturn(claims);

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        var authentication = seenAuthentication.get();
        assertThat(authentication.getUserId()).isEqualTo(USER_ID);
        assertThat(authentication.getEmail()).isEqualTo("holder@example.com");
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("Onboarding:Execute", "Certification:Upload");
    }

    @Test
    void filter_tokenWithoutPowers_authenticatesWithNoAuthorities() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(Map.of("sub", USER_ID.toString(), "email", "a@b.c"));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        assertThat(seenAuthentication.get().getAuthorities()).isEmpty();
    }

    @Test
    void filter_invalidToken_continuesUnauthenticated() {
        // Arrange
        when(tokenSigner.verify("bad-token")).thenThrow(new InvalidTokenException("Invalid JWT signature"));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer bad-token"), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
    }

    @Test
    void filter_noAuthorizationHeader_skipsVerification() {
        // Act
        var result = filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/credentials")), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verifyNoInteractions(tokenSigner);
        assertThat(seenAuthentication.get()).isNull();
    }

    @Test
    void filter_nonBearerScheme_skipsVerification() {
        // Act
        var result = filter.filter(exchangeWithAuthorization("Basic dXNlcjpwYXNz"), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verifyNoInteractions(tokenSigner);
    }

    @Test
    void filter_unexpectedVerifierFailure_propagates() {
        // Arrange
        when(tokenSigner.verify("token")).thenThrow(new IllegalStateException("JWT verifier not initialized"));

        // Act
        Mono<Void> result = filter.filter(exchangeWithAuthorization("Bearer token"), chain);

        // Assert
        StepVerifier.create(result).expectError(IllegalStateException.class).verify();
    }

    private static MockServerWebExchange exchangeWithAuthorization(String value) {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, value));
    }
}
