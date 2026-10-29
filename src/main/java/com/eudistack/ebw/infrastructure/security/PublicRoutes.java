package com.eudistack.ebw.infrastructure.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Routes reachable without a session access token. {@code SecurityConfig} permits them and
 * {@link JwtAuthenticationWebFilter} does not check the session of a bearer sent to them, so
 * one single list decides both.
 */
public final class PublicRoutes {

    public static final ServerWebExchangeMatcher MATCHER = ServerWebExchangeMatchers.matchers(
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,
                    "/api/v1/auth/register",
                    "/api/v1/auth/verify-email",
                    "/api/v1/auth/refresh",
                    // Registration ticket bearer: validated by the endpoints themselves.
                    "/api/v1/auth/passkeys/registration/options",
                    "/api/v1/auth/passkeys/registration",
                    // Sign-in with a passkey, with an optional registration ticket.
                    "/api/v1/auth/sessions/options",
                    "/api/v1/auth/sessions"),
            ServerWebExchangeMatchers.pathMatchers("/health", "/health/**"),
            // EUDISTACK-413: public wallet discovery endpoint (AC-03 — no auth required).
            // The canonical path is served by WellKnownCanonicalHandler at Netty level
            // before the security chain runs; these matchers are defense-in-depth for unit tests.
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/.well-known/wallet-config-metadata"),
            ServerWebExchangeMatchers.pathMatchers(HttpMethod.HEAD, "/.well-known/wallet-config-metadata"));

    private PublicRoutes() {}
}
