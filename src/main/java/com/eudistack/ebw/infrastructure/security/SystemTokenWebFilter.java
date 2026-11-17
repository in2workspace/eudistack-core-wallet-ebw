package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.infrastructure.adapter.verifier.VerifierUnavailableException;
import com.eudistack.ebw.infrastructure.controller.support.AuthProblems;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

/**
 * Authenticates {@code POST /onboarding-tickets} with a system token of the tenant's Verifier
 * (design §2.6, AD-9). Only that route: the session filter never accepts a system token (it is
 * not signed by this service), and this filter never accepts a session token (its {@code iss} is
 * not the Verifier's). The route is in {@link PublicRoutes} so the session chain lets it through.
 *
 * <p>On success the {@link SystemCaller} is stored in the exchange attribute
 * {@link #SYSTEM_CALLER_ATTRIBUTE}. Otherwise answers 401 {@code invalid_token}, 403
 * {@code insufficient_permission}, or 503 {@code service_unavailable} when the Verifier keys
 * cannot be read (ES-03); the rest of the service never depends on the Verifier.
 *
 * <p>The expected {@code iss} is the public origin of the request plus the Verifier base path,
 * as in the Issuer: the Verifier writes the URL the token was requested on as {@code iss}, and
 * the tenant's apps share their public host.
 */
@Slf4j
@Component
public class SystemTokenWebFilter implements WebFilter, Ordered {

    public static final String SYSTEM_CALLER_ATTRIBUTE = SystemTokenWebFilter.class.getName() + ".caller";
    static final String ONBOARDING_TICKETS_PATH = "/api/v1/onboarding-tickets"; // NOSONAR java:S1075
    /**
     * Matched as the handler mappings match it: a plain string comparison would let through the
     * variants Spring still routes to the controller (path parameters such as {@code ;x=1}).
     */
    private static final PathPattern ONBOARDING_TICKETS = PathPatternParser.defaultInstance.parse(ONBOARDING_TICKETS_PATH);
    /** After the Spring Security chain (-100) and the tenant filter (-200). */
    static final int ORDER = -50;
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String FORWARDED_PROTO = "X-Forwarded-Proto";
    private static final String FORWARDED_HOST = "X-Forwarded-Host";

    private final SystemTokenVerifier tokenVerifier;
    private final String verifierBasePath;
    private final ObjectMapper objectMapper;
    private final boolean trustForwardedHost;

    public SystemTokenWebFilter(SystemTokenVerifier tokenVerifier,
                                @Value("${ebw.verifier.base-path:/verifier}") String verifierBasePath,
                                ObjectMapper objectMapper,
                                @Value("${ebw.security.trust-forwarded-host:false}") boolean trustForwardedHost) {
        this.tokenVerifier = tokenVerifier;
        this.verifierBasePath = verifierBasePath;
        this.objectMapper = objectMapper;
        this.trustForwardedHost = trustForwardedHost;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var request = exchange.getRequest();
        if (!HttpMethod.POST.equals(request.getMethod())
                || !ONBOARDING_TICKETS.matches(request.getPath().pathWithinApplication())) {
            return chain.filter(exchange);
        }
        return Mono.deferContextual(ctx -> tokenVerifier.verify(bearer(request),
                        ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null),
                        publicOrigin(request) + verifierBasePath))
                .flatMap(caller -> {
                    exchange.getAttributes().put(SYSTEM_CALLER_ATTRIBUTE, caller);
                    return chain.filter(exchange);
                })
                .onErrorResume(SystemTokenRejectedException.class, e -> {
                    log.info("System token rejected on {}: {}", ONBOARDING_TICKETS_PATH, e.getReason());
                    return write(exchange, e.getStatus(), e.getType());
                })
                .onErrorResume(VerifierUnavailableException.class, e -> {
                    log.error("System token not checked, the Verifier keys are unavailable: {}", e.getMessage());
                    return write(exchange, HttpStatus.SERVICE_UNAVAILABLE, AuthProblems.SERVICE_UNAVAILABLE);
                });
    }

    private static String bearer(ServerHttpRequest request) {
        var header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return header != null && header.startsWith(BEARER_PREFIX) ? header.substring(BEARER_PREFIX.length()).trim()
                : null;
    }

    /** Scheme and host the caller used; behind the trusted proxy, its forwarded headers. */
    String publicOrigin(ServerHttpRequest request) {
        var uri = request.getURI();
        var scheme = uri.getScheme();
        var host = uri.getRawAuthority();
        if (trustForwardedHost) {
            scheme = firstValue(request.getHeaders().getFirst(FORWARDED_PROTO), scheme);
            host = firstValue(request.getHeaders().getFirst(FORWARDED_HOST), host);
        }
        return scheme + "://" + host;
    }

    private static String firstValue(String header, String fallback) {
        if (header == null || header.isBlank()) {
            return fallback;
        }
        return header.split(",")[0].trim();
    }

    private Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String type) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(AuthProblems.of(status, type));
        } catch (Exception _) {
            body = new byte[0];
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
