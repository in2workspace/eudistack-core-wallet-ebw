package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;

/**
 * Extracts the tenant identifier from the request hostname and stores it
 * in the Reactor subscriber context. Pattern: {tenant}.domain
 *
 * <p>When {@code ebw.security.trust-forwarded-host=true} (set via {@code TRUST_FORWARDED_HOST}
 * env var), the {@code X-Forwarded-Host} header is preferred. Only enable this flag when the
 * service is exclusively reachable through a trusted reverse proxy (e.g. AWS ALB) that sets
 * this header — direct client access must be blocked at the network level.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    private final boolean trustForwardedHost;

    public TenantDomainWebFilter(
            @Value("${ebw.security.trust-forwarded-host:false}") boolean trustForwardedHost) {
        this.trustForwardedHost = trustForwardedHost;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenant = extractTenantFromHostname(exchange);
        if (tenant != null && !tenant.isBlank()) {
            log.trace("Resolved tenant '{}' from request hostname", tenant);
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant));
        }
        log.trace("No tenant resolved from request hostname");
        return chain.filter(exchange);
    }

    private String extractTenantFromHostname(ServerWebExchange exchange) {
        String host = resolveHost(exchange);
        if (host == null || host.isBlank()) return null;

        String hostname = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;

        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) return null;

        String tenant = hostname.substring(0, dotIndex);
        if (!tenant.matches("^[a-zA-Z][a-zA-Z0-9_-]*$")) {
            log.warn("Invalid tenant identifier from hostname (must start with a letter): {}", tenant);
            return null;
        }
        return tenant.toLowerCase();
    }

    private String resolveHost(ServerWebExchange exchange) {
        if (trustForwardedHost) {
            String forwardedHost = exchange.getRequest().getHeaders().getFirst("X-Forwarded-Host");
            if (forwardedHost != null && !forwardedHost.isBlank()) return forwardedHost;
        }
        InetSocketAddress hostAddress = exchange.getRequest().getHeaders().getHost();
        return hostAddress != null ? hostAddress.getHostString() : null;
    }
}
