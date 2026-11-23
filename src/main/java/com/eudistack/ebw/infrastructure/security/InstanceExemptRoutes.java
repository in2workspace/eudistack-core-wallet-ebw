package com.eudistack.ebw.infrastructure.security;

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Authenticated routes that do not require the session to be bound to an active Wallet Instance (EUD-15
 * AD-3): only those of the session itself and of registering or binding the instance, the routes to get one.
 * Every other authenticated route answers 403 {@code instance_required} without a bound active instance, so a
 * new route of another functionality is protected without touching anything here (deny by default, OWASP
 * ASVS access control). Same pattern as {@link PublicRoutes} for the session.
 */
public final class InstanceExemptRoutes {

    public static final ServerWebExchangeMatcher MATCHER = ServerWebExchangeMatchers.pathMatchers(
            "/api/v1/auth/**",
            "/api/v1/wallet-instances",
            "/api/v1/wallet-instances/**");

    private InstanceExemptRoutes() {}
}
