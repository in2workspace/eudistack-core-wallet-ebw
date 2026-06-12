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
 * Extracts the tenant identifier from the request and stores it in the Reactor
 * subscriber context.
 *
 * <p>Resolution order when {@code ebw.security.trust-forwarded-host=true}:
 * <ol>
 *   <li>First subdomain of the {@code X-Forwarded-Host} header (e.g. {@code acme} from
 *       {@code acme.example.com}).
 *   <li>Value of the {@code X-Tenant} header, used verbatim as the tenant identifier.
 * </ol>
 * When the property is {@code false} (default), the tenant is extracted from the first
 * subdomain of the {@code Host} header only.
 *
 * <p>Only enable {@code trust-forwarded-host} when the service is exclusively reachable
 * through a trusted reverse proxy (e.g. AWS ALB) that controls these headers — direct
 * client access must be blocked at the network level.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    public static final String HEADER_X_FORWARDED_HOST = "X-Forwarded-Host";
    public static final String HEADER_X_TENANT = "X-Tenant";

    private final boolean trustForwardedHost;

    public TenantDomainWebFilter(
            @Value("${ebw.security.trust-forwarded-host:false}") boolean trustForwardedHost) {
        this.trustForwardedHost = trustForwardedHost;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenant = resolveTenant(exchange);
        if (tenant != null) {
            log.trace("Resolved tenant '{}' from request", tenant);
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant));
        }
        log.trace("No tenant resolved from request");
        return chain.filter(exchange);
    }

    String resolveTenant(ServerWebExchange exchange) {
        if (trustForwardedHost) {
            String fwdHost = exchange.getRequest().getHeaders().getFirst(HEADER_X_FORWARDED_HOST);
            if (fwdHost != null && !fwdHost.isBlank()) {
                String tenant = subdomainOf(fwdHost);
                if (tenant != null) return tenant;
            }
            String xTenant = exchange.getRequest().getHeaders().getFirst(HEADER_X_TENANT);
            if (xTenant != null && !xTenant.isBlank()) {
                return validateTenant(xTenant.trim());
            }
            return null;
        }
        InetSocketAddress addr = exchange.getRequest().getHeaders().getHost();
        return addr != null ? subdomainOf(addr.getHostString()) : null;
    }

    private String subdomainOf(String host) {
        if (host == null || host.isBlank()) return null;
        String hostname = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) return null;
        return validateTenant(hostname.substring(0, dotIndex));
    }

    private String validateTenant(String candidate) {
        if (!candidate.matches("^[a-zA-Z][a-zA-Z0-9_-]*$")) {
            log.warn("Invalid tenant identifier (must start with a letter): {}", candidate);
            return null;
        }
        return candidate.toLowerCase();
    }
}
