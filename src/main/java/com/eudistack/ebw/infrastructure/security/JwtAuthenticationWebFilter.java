package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Authenticates the request with the session access token in {@code Authorization: Bearer}.
 *
 * <p>The request stays unauthenticated (and protected routes answer 401) when the bearer is
 * not a valid JWT — for instance a registration ticket, which the ticket endpoints validate
 * themselves —, when the token belongs to another tenant than the request's
 * ({@link ReactorContextKeys#TENANT_DOMAIN}, set by {@code TenantDomainWebFilter}, which runs
 * before the security chain), or when it lacks the session claims {@code sid} and {@code pkid}.
 */
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationWebFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenSigner tokenSigner;

    public JwtAuthenticationWebFilter(TokenSigner tokenSigner) {
        this.tokenSigner = tokenSigner;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return chain.filter(exchange);
        }

        var token = authHeader.substring(BEARER_PREFIX.length());
        return Mono.<Map<String, Object>>fromCallable(() -> tokenSigner.verify(token))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(claims -> Mono.deferContextual(ctx -> {
                    String requestTenant = ctx.getOrDefault(ReactorContextKeys.TENANT_DOMAIN, null);
                    return Mono.justOrEmpty(toAuthentication(claims, requestTenant));
                }))
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .onErrorResume(InvalidTokenException.class, e -> Mono.just(Optional.empty()))
                .flatMap(authentication -> authentication
                        .map(auth -> chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
                        .orElseGet(() -> chain.filter(exchange)));
    }

    private JwtAuthenticationToken toAuthentication(Map<String, Object> claims, String requestTenant) {
        var tenant = claims.get("tenant");
        if (requestTenant == null || !requestTenant.equals(tenant)) {
            log.debug("Access token rejected: tenant does not match the request");
            return null;
        }
        var userId = parseUuid(claims.get("sub"));
        var sessionId = parseUuid(claims.get("sid"));
        var passkeyId = parseUuid(claims.get("pkid"));
        if (userId == null || sessionId == null || passkeyId == null) {
            log.debug("Access token rejected: missing session claims");
            return null;
        }
        return new JwtAuthenticationToken(userId, (String) claims.get("email"), sessionId, passkeyId,
                extractAuthorities(claims));
    }

    private static UUID parseUuid(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Extracts PBAC powers from the JWT {@code powers} claim (string array) and maps them
     * to {@link GrantedAuthority} instances. Returns an empty list if the claim is absent.
     */
    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        var powers = claims.get("powers");
        if (powers instanceof List<?> list) {
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(p -> (GrantedAuthority) new SimpleGrantedAuthority((String) p))
                    .collect(Collectors.toList());
        }
        return List.of();
    }
}
