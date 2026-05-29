package com.eudistack.ebw.wallet.profile.infrastructure.web;

import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.stereotype.Component;

/**
 * Registers a Reactor Netty route for the canonical
 * {@code /.well-known/wallet-config-metadata} path before Spring Boot's
 * {@code spring.webflux.base-path=/business-wallet} filter takes effect.
 *
 * <h3>Why a Netty-level route is necessary</h3>
 * <p>Spring Boot 3.5 implements {@code spring.webflux.base-path} by wrapping the
 * {@link org.springframework.http.server.reactive.HttpHandler} in a
 * {@code ContextPathCompositeHandler} and registering it as a Reactor Netty route
 * with a path-starts-with predicate. Requests whose paths do not start with the
 * configured prefix ({@code /business-wallet}) are rejected by the Reactor Netty
 * routing layer <em>before</em> the Spring WebFlux {@code WebFilter} chain runs — making
 * it impossible for a {@code WebFilter} at any order to intercept the RFC 8615 canonical
 * path {@code /.well-known/wallet-config-metadata}.
 *
 * <h3>Mechanism</h3>
 * <p>A {@link org.springframework.boot.web.embedded.netty.NettyRouteProvider} is added via
 * {@link NettyReactiveWebServerFactory#addRouteProviders}. Route providers are
 * applied by {@code NettyWebServer} <em>before</em> the default Spring catch-all route, so
 * {@code GET /.well-known/wallet-config-metadata} is matched first and delegated to
 * {@link WellKnownCanonicalHandler} through a {@link ReactorHttpHandlerAdapter}.
 *
 * <h3>Shadow-path blocking</h3>
 * <p>The prefixed shadow path
 * {@code /business-wallet/.well-known/wallet-config-metadata} is NOT matched by this
 * route (different path). It falls through to the Spring handler, where
 * {@link WellKnownWebFilter} intercepts it at {@link org.springframework.core.Ordered#HIGHEST_PRECEDENCE}
 * and returns 404 (R-413-1).
 *
 * <p>See technical-design.md §3.5 AD-413-1 and acceptance-criteria.md AC-03 / R-413-1.
 */
@Component
public class WellKnownNettyRouteCustomizer
        implements WebServerFactoryCustomizer<NettyReactiveWebServerFactory> {

    private final WellKnownCanonicalHandler handler;

    public WellKnownNettyRouteCustomizer(WellKnownCanonicalHandler handler) {
        this.handler = handler;
    }

    @Override
    public void customize(NettyReactiveWebServerFactory factory) {
        // handler::handle is a method reference to WellKnownCanonicalHandler.handle(), which
        // satisfies HttpHandler's @FunctionalInterface without making that class implement
        // HttpHandler directly. If WellKnownCanonicalHandler were to implement HttpHandler,
        // Spring Boot's @ConditionalOnMissingBean(HttpHandler.class) guard would prevent
        // HttpHandlerAutoConfiguration from creating the ContextPathCompositeHandler, breaking
        // all /business-wallet/** routes (the ALWAYS catch-all would delegate to
        // WellKnownCanonicalHandler instead of to Spring's DispatcherHandler).
        ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(handler::handle);
        factory.addRouteProviders(routes -> routes
                .get(WalletProfileQueryController.WELL_KNOWN_PATH, adapter::apply)
                .head(WalletProfileQueryController.WELL_KNOWN_PATH, adapter::apply)
        );
    }
}
