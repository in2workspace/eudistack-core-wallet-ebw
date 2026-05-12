package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.adapter.properties.CorsProperties;
import com.eudistack.ebw.infrastructure.security.AdminApiKeyAuthenticationWebFilter;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /** Authority required to call the admin wallet-tenant-config endpoints (SEC-B2). */
    private static final String TENANT_CONFIG_WRITE = "SCOPE_tenant.config.write";

    private final JwtAuthenticationWebFilter jwtAuthFilter;
    private final AdminApiKeyAuthenticationWebFilter adminApiKeyFilter;
    private final CorsProperties corsProperties;

    public SecurityConfig(JwtAuthenticationWebFilter jwtAuthFilter,
                          AdminApiKeyAuthenticationWebFilter adminApiKeyFilter,
                          CorsProperties corsProperties) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.adminApiKeyFilter = adminApiKeyFilter;
        this.corsProperties = corsProperties;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                )
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/verify-email").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/logout").permitAll()
                        .pathMatchers("/health", "/health/**").permitAll()
                        .pathMatchers(HttpMethod.GET, "/.well-known/wallet-tenant-config").permitAll()
                        // SEC-B2: the admin write endpoints require the SCOPE_tenant.config.write
                        // authority. That authority is granted exclusively by
                        // AdminApiKeyAuthenticationWebFilter when a valid X-Admin-Api-Key header is
                        // presented (the JWT filter never mints it), so this rule + the
                        // @PreAuthorize on the handlers are defence in depth over the API-key check.
                        .pathMatchers("/admin/**").hasAuthority(TENANT_CONFIG_WRITE)
                        .anyExchange().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                // Runs immediately after the JWT filter, i.e. just before the authorization checks:
                // for /admin/** it establishes (and overrides) the security context with the
                // admin authority, or short-circuits with 401; for every other path it is a no-op.
                .addFilterAfter(adminApiKeyFilter, SecurityWebFiltersOrder.AUTHENTICATION)
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

    private CorsConfigurationSource corsConfigurationSource() {
        var config = new CorsConfiguration();
        var origins = Arrays.asList(corsProperties.allowedOrigins().split(","));
        config.setAllowedOriginPatterns(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Api-Version"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
