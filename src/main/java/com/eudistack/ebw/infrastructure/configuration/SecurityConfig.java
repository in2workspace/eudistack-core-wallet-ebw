package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.security.CorsOriginsLoader;
import com.eudistack.ebw.infrastructure.security.InvalidSessionResponse;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.eudistack.ebw.infrastructure.security.PublicRoutes;
import com.eudistack.ebw.infrastructure.security.TenantCorsConfigurationSource;
import com.eudistack.ebw.infrastructure.security.TenantOrigins;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtAuthenticationWebFilter jwtAuthFilter;
    private final CorsConfigurationSource corsConfigurationSource;
    private final RefreshCookies refreshCookies;
    private final ObjectMapper objectMapper;

    public SecurityConfig(JwtAuthenticationWebFilter jwtAuthFilter,
                          CorsConfigurationSource corsConfigurationSource,
                          RefreshCookies refreshCookies,
                          ObjectMapper objectMapper) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.corsConfigurationSource = corsConfigurationSource;
        this.refreshCookies = refreshCookies;
        this.objectMapper = objectMapper;
    }

    /** CORS of the tenant of each request; the file/env list only for health and wallet discovery. */
    @Bean
    static CorsConfigurationSource tenantCorsConfigurationSource(TenantDomainWebFilter tenantResolver,
                                                                 TenantOrigins tenantOrigins,
                                                                 CorsOriginsLoader corsOriginsLoader) {
        return new TenantCorsConfigurationSource(tenantResolver, tenantOrigins::originsOf,
                corsOriginsLoader.loadOrigins());
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // CSRF: the API authenticates with a Bearer access token in Authorization, which a
                // cross-site form cannot send. The only cookie is the __Host- refresh cookie
                // (SameSite=Strict); the endpoints that read it (refresh, end session, and registration
                // and sign-in, which end its session) also require the X-Wallet-Request: 1 header, which
                // a cross-site form cannot set without a CORS preflight, and CORS only admits the
                // tenant's origins. Spring's token-based CSRF is therefore not needed.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> unauthenticated(exchange))
                        .accessDeniedHandler((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                )
                .authorizeExchange(exchanges -> exchanges
                        .matchers(PublicRoutes.MATCHER).permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .headers(headers -> headers
                        .hsts(hsts -> {})
                        .frameOptions(frame -> frame.mode(org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                        .contentTypeOptions(contentType -> {})
                        .cache(cache -> cache.disable())
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'"))
                        .referrerPolicy(referrer -> referrer.policy(org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .permissionsPolicy(pp -> pp.policy("camera=(), microphone=(), geolocation=()"))
                )
                .build();
    }

    /**
     * 401 without body, except on the session endpoints of the contract, which answer the
     * {@code invalid_session} problem and clear the refresh cookie.
     */
    private Mono<Void> unauthenticated(ServerWebExchange exchange) {
        if (!InvalidSessionResponse.isSessionEndpoint(exchange)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return InvalidSessionResponse.write(exchange, objectMapper, refreshCookies);
    }
}
