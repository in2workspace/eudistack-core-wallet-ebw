package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;
import java.util.function.Function;

/**
 * CORS per tenant: a request of a tenant only admits the origins of that tenant's Wallet App
 * ({@code ebw.webauthn.origins}, default {@code https://<rp_id>}), resolved from the request the
 * same way as {@link TenantDomainWebFilter} (including the trusted proxy headers). The global list
 * ({@code cors-origins.yaml} plus {@code CORS_ORIGINS}) only applies to the paths that are not
 * tenant data: health and wallet discovery. An unknown tenant admits no cross-origin request.
 */
public class TenantCorsConfigurationSource implements CorsConfigurationSource {

    private static final List<String> NON_TENANT_PATHS = List.of("/health", "/.well-known/");

    private final TenantDomainWebFilter tenantResolver;
    private final Function<String, List<String>> tenantOrigins;
    private final List<String> globalOrigins;

    public TenantCorsConfigurationSource(TenantDomainWebFilter tenantResolver,
                                         Function<String, List<String>> tenantOrigins,
                                         List<String> globalOrigins) {
        this.tenantResolver = tenantResolver;
        this.tenantOrigins = tenantOrigins;
        this.globalOrigins = List.copyOf(globalOrigins);
    }

    @Override
    public CorsConfiguration getCorsConfiguration(ServerWebExchange exchange) {
        var path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (NON_TENANT_PATHS.stream().anyMatch(path::startsWith)) {
            return configuration(globalOrigins);
        }
        var tenant = tenantResolver.resolveTenant(exchange);
        return configuration(tenant == null ? List.of() : tenantOrigins.apply(tenant));
    }

    private static CorsConfiguration configuration(List<String> origins) {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Api-Version", "X-Wallet-Request"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        return config;
    }
}
