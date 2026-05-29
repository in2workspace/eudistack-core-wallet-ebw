package com.eudistack.ebw.wallet.profile.infrastructure.web;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * WebFilter that blocks external access to the shadow path
 * {@code /business-wallet/.well-known/wallet-config-metadata} (R-413-1).
 *
 * <h3>Context</h3>
 * <p>The canonical path {@code /.well-known/wallet-config-metadata} is served by
 * {@link WellKnownCanonicalHandler} at the Reactor Netty routing level — registered
 * by {@link WellKnownNettyRouteCustomizer} before the
 * {@code spring.webflux.base-path=/business-wallet} filter applies (AD-413-1).
 *
 * <h3>Shadow-path mechanics</h3>
 * <p>When a request arrives at {@code /business-wallet/.well-known/wallet-config-metadata}:
 * <ol>
 *   <li>The Netty route for {@code /.well-known/...} does <em>not</em> match (different prefix).
 *   <li>The request falls through to the Spring catch-all handler, where
 *       {@code ContextPathCompositeHandler} strips {@code /business-wallet} and sets it as
 *       the context path.
 *   <li>{@code exchange.getRequest().getPath().value()} returns the <em>full</em> original
 *       path {@code /business-wallet/.well-known/wallet-config-metadata} — {@code value()}
 *       includes the context-path prefix.
 *   <li>This filter matches that full path and returns 404 before any handler mapping occurs.
 * </ol>
 *
 * <p>Runs at {@link Ordered#HIGHEST_PRECEDENCE} to intercept before Spring Security
 * (order {@code -100}) and avoid authentication challenges on the blocked path.
 *
 * <p>See technical-design.md §3.5 AD-413-1 / R-413-1 and acceptance-criteria.md R-413-1.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WellKnownWebFilter implements WebFilter {

    private static final String SHADOW_PATH =
            "/business-wallet" + WalletProfileQueryController.WELL_KNOWN_PATH;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (SHADOW_PATH.equals(exchange.getRequest().getPath().value())) {
            exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }
}
