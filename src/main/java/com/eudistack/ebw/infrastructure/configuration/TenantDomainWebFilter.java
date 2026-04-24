package com.eudistack.ebw.infrastructure.configuration;

import lombok.extern.slf4j.Slf4j;
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
 * <p>Examples:
 * <ul>
 *   <li>{@code kpmg.127.0.0.1.nip.io} → {@code kpmg}</li>
 *   <li>{@code dome.eudistack.net} → {@code dome}</li>
 * </ul>
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    public static final String TENANT_DOMAIN_CONTEXT_KEY = "tenantDomain";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenant = extractTenantFromHostname(exchange);
        if (tenant != null && !tenant.isBlank()) {
            log.trace("Resolved tenant '{}' from request hostname", tenant);
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
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
        if (!tenant.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("Invalid tenant identifier from hostname: {}", tenant);
            return null;
        }
        return tenant.toLowerCase();
    }

    private String resolveHost(ServerWebExchange exchange) {
        String forwardedHost = exchange.getRequest().getHeaders().getFirst("X-Forwarded-Host");
        if (forwardedHost != null && !forwardedHost.isBlank()) return forwardedHost;
        InetSocketAddress hostAddress = exchange.getRequest().getHeaders().getHost();
        return hostAddress != null ? hostAddress.getHostString() : null;
    }
}
