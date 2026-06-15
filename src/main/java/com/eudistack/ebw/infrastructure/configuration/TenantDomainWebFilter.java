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
 * Resolves the tenant identifier from the request and stores it in the Reactor
 * subscriber context.
 *
 * <p>Resolution order when {@code ebw.security.trust-forwarded-host=true}:
 * <ol>
 *   <li>Value of the {@code X-Tenant} header, trimmed, validated and normalized
 *       to lowercase.</li>
 *   <li>First subdomain of the {@code X-Forwarded-Host} header, validated and
 *       normalized to lowercase (e.g. {@code acme} from {@code acme.example.com}).</li>
 *   <li>First subdomain of the {@code Host} header, validated and normalized
 *       to lowercase.</li>
 * </ol>
 *
 * <p>When the property is {@code false} (default), the tenant is extracted from
 * the first subdomain of the {@code Host} header only.
 *
 * <p>A valid tenant must start with a letter and may contain only letters,
 * digits, hyphens and underscores.
 *
 * <p>Only enable {@code trust-forwarded-host} when the service is exclusively
 * reachable through a trusted reverse proxy (e.g. AWS ALB) that controls these
 * headers — direct client access must be blocked at the network level.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    public static final String HEADER_X_FORWARDED_HOST = "X-Forwarded-Host";
    public static final String HEADER_X_TENANT = "X-Tenant";

    private static final String TENANT_PATTERN = "^[a-zA-Z][a-zA-Z0-9_-]*$";

    private final boolean trustForwardedHost;

    public TenantDomainWebFilter(
            @Value("${ebw.security.trust-forwarded-host:false}") boolean trustForwardedHost) {
        this.trustForwardedHost = trustForwardedHost;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenant = resolveTenant(exchange);
        if (tenant != null) {
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant));
        }

        log.trace("No valid tenant resolved from request; continuing without tenant in Reactor context");
        return chain.filter(exchange);
    }

    String resolveTenant(ServerWebExchange exchange) {
        if (trustForwardedHost) {
            String xTenant = exchange.getRequest().getHeaders().getFirst(HEADER_X_TENANT);

            if (xTenant != null && !xTenant.isBlank()) {
                String tenant = validateTenant(xTenant.trim(), HEADER_X_TENANT + " header");

                if (tenant != null) {
                    log.debug("Resolved tenant '{}' from {} header", tenant, HEADER_X_TENANT);
                    return tenant;
                }
            }

            String fwdHost = exchange.getRequest().getHeaders().getFirst(HEADER_X_FORWARDED_HOST);

            if (fwdHost != null && !fwdHost.isBlank()) {
                String tenant = subdomainOf(fwdHost, HEADER_X_FORWARDED_HOST + " header");

                if (tenant != null) {
                    log.debug("Resolved tenant '{}' from {} header", tenant, HEADER_X_FORWARDED_HOST);
                    return tenant;
                }
            }

            log.trace("No tenant resolved from {} or {} headers; falling back to Host header",
                    HEADER_X_TENANT, HEADER_X_FORWARDED_HOST);
        }

        return resolveTenantFromHostHeader(exchange);
    }

    private String resolveTenantFromHostHeader(ServerWebExchange exchange) {
        InetSocketAddress addr = exchange.getRequest().getHeaders().getHost();
        if (addr == null) {
            return null;
        }

        String tenant = subdomainOf(addr.getHostString(), "Host header");
        if (tenant != null) {
            log.debug("Resolved tenant '{}' from Host header", tenant);
        }
        return tenant;
    }

    private String subdomainOf(String host, String source) {
        if (host == null || host.isBlank()) {
            return null;
        }

        String hostname = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) {
            return null;
        }

        return validateTenant(hostname.substring(0, dotIndex), source);
    }

    private String validateTenant(String candidate, String source) {
        if (!candidate.matches(TENANT_PATTERN)) {
            log.warn("Invalid tenant identifier from {}: {}. It must start with a letter and contain only letters, digits, hyphens and underscores",
                    source, candidate);
            return null;
        }
        return candidate.toLowerCase();
    }
}