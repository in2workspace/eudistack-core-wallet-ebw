package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.service.SessionRevocationChecker;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The core of the session-revocation-not-hot fix: a JWT that is still valid by
 * signature+exp must nonetheless be rejected once its backing session (the refresh-token
 * row it was minted from, carried as the "sid" claim) has been revoked — see
 * {@link SessionRevocationChecker}. Before this filter change, revoking a passkey/device/
 * session only stopped future refreshes; the access token already handed out kept being
 * accepted until its own `exp`.
 */
class JwtAuthenticationWebFilterTest {

    private TokenSigner tokenSigner;
    private SessionRevocationChecker sessionRevocationChecker;
    private JwtAuthenticationWebFilter filter;

    @BeforeEach
    void setUp() {
        tokenSigner = mock(TokenSigner.class);
        sessionRevocationChecker = mock(SessionRevocationChecker.class);
        filter = new JwtAuthenticationWebFilter(tokenSigner, sessionRevocationChecker, new TenantDomainWebFilter(false));
    }

    @Test
    void noAuthorizationHeader_continuesWithoutAuthenticating() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

        assertThat(authenticationWasSet(exchange)).isFalse();
    }

    @Test
    void invalidToken_continuesWithoutAuthenticating() {
        var exchange = bearerRequest("garbage-token");
        when(tokenSigner.verify("garbage-token")).thenThrow(new InvalidTokenException("bad token"));

        assertThat(authenticationWasSet(exchange)).isFalse();
    }

    @Test
    void validTokenWithoutSidClaim_authenticates() {
        // Tokens issued before this fix carry no "sid" — treated as valid so already-
        // issued sessions aren't force-logged-out on deploy; every token minted from
        // then on carries one.
        var exchange = bearerRequest("legacy-token");
        when(tokenSigner.verify("legacy-token")).thenReturn(Map.of(
                "sub", UUID.randomUUID().toString(), "email", "user@example.com"));

        assertThat(authenticationWasSet(exchange)).isTrue();
    }

    @Test
    void validTokenWithActiveSession_authenticates() {
        var sid = UUID.randomUUID();
        var exchange = bearerRequest("good-token");
        when(tokenSigner.verify("good-token")).thenReturn(Map.of(
                "sub", UUID.randomUUID().toString(), "email", "user@example.com", "sid", sid.toString()));
        when(sessionRevocationChecker.isValid(sid)).thenReturn(Mono.just(true));

        assertThat(authenticationWasSet(exchange)).isTrue();
    }

    @Test
    void validTokenWithRevokedSession_doesNotAuthenticate() {
        var sid = UUID.randomUUID();
        var exchange = bearerRequest("revoked-session-token");
        when(tokenSigner.verify("revoked-session-token")).thenReturn(Map.of(
                "sub", UUID.randomUUID().toString(), "email", "user@example.com", "sid", sid.toString()));
        when(sessionRevocationChecker.isValid(sid)).thenReturn(Mono.just(false));

        assertThat(authenticationWasSet(exchange)).isFalse();
    }

    private static MockServerWebExchange bearerRequest(String token) {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/")
                .header("Authorization", "Bearer " + token)
                .build());
    }

    /** Runs the filter and reports whether the downstream chain saw an Authentication. */
    private boolean authenticationWasSet(MockServerWebExchange exchange) {
        boolean[] hasAuth = {false};
        filter.filter(exchange, ex -> ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> hasAuth[0] = ctx.getAuthentication() != null)
                .then()
        ).block();
        return hasAuth[0];
    }
}
