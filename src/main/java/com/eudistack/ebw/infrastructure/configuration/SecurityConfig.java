package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.eudistack.ebw.infrastructure.controller.support.RefreshCookies;
import com.eudistack.ebw.infrastructure.security.CorsOriginsLoader;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationWebFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /** Session endpoints whose 401 is the contract's {@code invalid_session} problem. */
    private static final String SESSIONS_PATH = "/api/v1/auth/sessions/";

    private final JwtAuthenticationWebFilter jwtAuthFilter;
    private final List<String> allowedOrigins;
    private final RefreshCookies refreshCookies;
    private final ObjectMapper objectMapper;

    public SecurityConfig(JwtAuthenticationWebFilter jwtAuthFilter,
                          CorsOriginsLoader corsOriginsLoader,
                          RefreshCookies refreshCookies,
                          ObjectMapper objectMapper) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.allowedOrigins = corsOriginsLoader.loadOrigins();
        this.refreshCookies = refreshCookies;
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // CSRF: the API authenticates with a Bearer access token in Authorization, which a
                // cross-site form cannot send. The only cookie is the refresh cookie (SameSite=Strict,
                // Path=/api/v1/auth); the endpoints that use it (refresh, end session) also require the
                // X-Wallet-Request: 1 header, which a cross-site form cannot set without a CORS
                // preflight, and CORS only admits the configured origins. Spring's token-based CSRF is
                // therefore not needed.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> unauthenticated(exchange))
                        .accessDeniedHandler((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                )
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/verify-email").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/refresh").permitAll()
                        // Registration ticket bearer: validated by the endpoints themselves.
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/registration/options").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/passkeys/registration").permitAll()
                        // Sign-in with a passkey, with an optional registration ticket.
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/sessions/options").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/sessions").permitAll()
                        .pathMatchers("/health", "/health/**").permitAll()
                        // EUDISTACK-413: public wallet discovery endpoint (AC-03 — no auth required).
                        // The canonical path is served by WellKnownCanonicalHandler at Netty level
                        // before this chain runs; these matchers are defense-in-depth for unit tests.
                        .pathMatchers(HttpMethod.GET, "/.well-known/wallet-config-metadata").permitAll()
                        .pathMatchers(HttpMethod.HEAD, "/.well-known/wallet-config-metadata").permitAll()
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
     * Only the configured origins ({@code cors-origins.yaml} plus {@code CORS_ORIGINS}), with
     * credentials for the refresh cookie. No wildcard.
     */
    CorsConfigurationSource corsConfigurationSource() {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Api-Version", "X-Wallet-Request"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    /**
     * 401 without body, except on the session endpoints of the contract, which answer the
     * {@code invalid_session} problem and clear the refresh cookie.
     */
    private Mono<Void> unauthenticated(ServerWebExchange exchange) {
        var response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        var path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (!path.startsWith(SESSIONS_PATH)) {
            return response.setComplete();
        }
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().add(HttpHeaders.SET_COOKIE, refreshCookies.clear().toString());
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(AuthProblems.of(HttpStatus.UNAUTHORIZED, AuthProblems.INVALID_SESSION));
        } catch (Exception e) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
