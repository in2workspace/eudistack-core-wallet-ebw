package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
    private static final UUID SESSION_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();
    private static final String TENANT = "sandbox";

    private TokenSigner tokenSigner;
    private ActiveSessionChecker activeSessionChecker;
    private JwtAuthenticationWebFilter filter;
    private AtomicReference<JwtAuthenticationToken> seenAuthentication;
    private WebFilterChain chain;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        activeSessionChecker = mock(ActiveSessionChecker.class);
        org.mockito.Mockito.lenient().when(activeSessionChecker.isActive(org.mockito.ArgumentMatchers.any()))
                .thenReturn(Mono.just(true));
        filter = new JwtAuthenticationWebFilter(tokenSigner, activeSessionChecker,
                new com.fasterxml.jackson.databind.ObjectMapper(), new RefreshCookies());
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
        claims.put("tenant", TENANT);
        claims.put("sid", SESSION_ID.toString());
        claims.put("pkid", PASSKEY_ID.toString());
        claims.put("powers", List.of("Onboarding:Execute", 42, "Certification:Upload"));
        when(tokenSigner.verify("good-token")).thenReturn(claims);

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        var authentication = seenAuthentication.get();
        assertThat(authentication.getUserId()).isEqualTo(USER_ID);
        assertThat(authentication.getSessionId()).isEqualTo(SESSION_ID);
        assertThat(authentication.getPasskeyId()).isEqualTo(PASSKEY_ID);
        assertThat(authentication.getEmail()).isEqualTo("holder@example.com");
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("Onboarding:Execute", "Certification:Upload");
    }

    @Test
    void filter_tokenWithoutPowers_authenticatesWithNoAuthorities() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims(TENANT));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        assertThat(seenAuthentication.get().getAuthorities()).isEmpty();
    }

    @Test
    void filter_tokenOfAnotherTenant_continuesUnauthenticated() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims("othertenant"));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
    }

    @Test
    void filter_requestWithoutTenant_continuesUnauthenticated() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims(TENANT));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(result).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
    }

    @Test
    void filter_tokenWithoutSessionClaims_continuesUnauthenticated() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(Map.of("sub", USER_ID.toString(), "email", "a@b.c",
                "tenant", TENANT));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer good-token"), chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
    }

    @Test
    void filter_registrationTicketBearer_continuesUnauthenticated() {
        // Arrange
        when(tokenSigner.verify("opaqueTicket")).thenThrow(new InvalidTokenException("Malformed JWT"));

        // Act
        var result = filter.filter(exchangeWithAuthorization("Bearer opaqueTicket"), chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
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

    private static Map<String, Object> sessionClaims(String tenant) {
        return Map.of("sub", USER_ID.toString(), "email", "a@b.c", "tenant", tenant,
                "sid", SESSION_ID.toString(), "pkid", PASSKEY_ID.toString());
    }

    private static Mono<Void> inTenant(Mono<Void> result, String tenant) {
        return result.contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant));
    }

    private static MockServerWebExchange exchangeWithAuthorization(String value) {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/credentials")
                .header(HttpHeaders.AUTHORIZATION, value));
    }

    @Test
    void filter_endedSessionOnSensitiveRoute_returnsInvalidSessionProblem() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims(TENANT));
        when(activeSessionChecker.isActive(SESSION_ID)).thenReturn(Mono.just(false));
        var exchange = exchangeWithAuthorization("Bearer good-token");

        // Act
        var result = filter.filter(exchange, chain);

        // Assert
        StepVerifier.create(inTenant(result, TENANT)).verifyComplete();
        assertThat(seenAuthentication.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(401);
        StepVerifier.create(exchange.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body).contains("invalid_session")).verifyComplete();
        assertThat(exchange.getResponse().getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void filter_endedSessionSigningOut_returnsInvalidSessionAndClearsTheRefreshCookie() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims(TENANT));
        when(activeSessionChecker.isActive(SESSION_ID)).thenReturn(Mono.just(false));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.delete("/api/v1/auth/sessions/current")
                .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));

        // Act
        StepVerifier.create(inTenant(filter.filter(exchange, chain), TENANT)).verifyComplete();

        // Assert
        assertThat(seenAuthentication.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(401);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .startsWith(RefreshCookies.NAME + "=").contains("Max-Age=0");
    }

    @ParameterizedTest
    @CsvSource({
            "/api/v1/auth/sessions/current, true",
            "/api/v1/auth/sessions/others, true",
            "/api/v1/auth/sessions/currently, false",
            "/api/v1/auth/sessions/options, false",
            "/api/v1/auth/sessions, false",
            "/api/v1/credentials, true",
            "/api/v1/credentials/abc, true",
            "/api/v1/credentialsx, false",
            "/api/v1/keys/passkey-prf/onboarding/init, true",
            "/api/v1/keys, false"
    })
    void isSensitive_path_matchesWholeSegmentsOnly(String path, boolean sensitive) {
        // Act + Assert
        assertThat(JwtAuthenticationWebFilter.isSensitive(path)).isEqualTo(sensitive);
    }

    @Test
    void filter_endedSessionOnNonSensitiveRoute_isNotChecked() {
        // Arrange
        when(tokenSigner.verify("good-token")).thenReturn(sessionClaims(TENANT));
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/v1/activity")
                .header(HttpHeaders.AUTHORIZATION, "Bearer good-token"));

        // Act
        StepVerifier.create(inTenant(filter.filter(exchange, chain), TENANT)).verifyComplete();

        // Assert
        verifyNoInteractions(activeSessionChecker);
        assertThat(seenAuthentication.get()).isNotNull();
    }
}
