package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.service.SessionRevocationChecker;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.eudistack.ebw.infrastructure.configuration.TenantDomainWebFilter;
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
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenSigner tokenSigner;
    private final SessionRevocationChecker sessionRevocationChecker;
    private final TenantDomainWebFilter tenantDomainWebFilter;

    public JwtAuthenticationWebFilter(TokenSigner tokenSigner,
                                      SessionRevocationChecker sessionRevocationChecker,
                                      TenantDomainWebFilter tenantDomainWebFilter) {
        this.tokenSigner = tokenSigner;
        this.sessionRevocationChecker = sessionRevocationChecker;
        this.tenantDomainWebFilter = tenantDomainWebFilter;
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
                .flatMap(claims -> checkSessionValidity(exchange, claims)
                        .flatMap(valid -> valid.booleanValue()
                                ? authenticate(exchange, chain, claims)
                                : chain.filter(exchange)))
                .onErrorResume(InvalidTokenException.class, e -> chain.filter(exchange));
    }

    /**
     * A signature+exp-valid JWT is not enough: its backing session (the refresh-token row
     * it was minted from) may have been revoked since — passkey/device deletion, "close
     * sessions", logout, or reuse-detection — see SessionRevocationChecker. Tokens issued
     * before this check existed carry no "sid" claim; treated as valid so already-issued
     * sessions aren't force-logged-out on deploy — every token minted from then on carries
     * one, and legacy ones age out naturally within one access-token TTL.
     *
     * <p>This filter runs inside Spring Security's chain, which is ordered before
     * {@link TenantDomainWebFilter} (a plain {@code @Component} with no explicit order) —
     * so the tenant is not yet in the Reactor Context here the way it is by the time a
     * controller/workflow runs. {@code refresh_token} is a per-tenant table, so the lookup
     * would otherwise hit the wrong (default) schema. Reusing
     * {@link TenantDomainWebFilter#resolveTenant} and writing it just around this one call
     * scopes it correctly without reordering the global filter chain.
     */
    private Mono<Boolean> checkSessionValidity(ServerWebExchange exchange, Map<String, Object> claims) {
        var sid = (String) claims.get("sid");
        if (sid == null) {
            return Mono.just(true);
        }
        var tenant = tenantDomainWebFilter.resolveTenant(exchange);
        return sessionRevocationChecker.isValid(UUID.fromString(sid))
                .contextWrite(ctx -> tenant != null ? ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant) : ctx);
    }

    private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Map<String, Object> claims) {
        var userId = UUID.fromString((String) claims.get("sub"));
        var email = (String) claims.get("email");
        var authorities = extractAuthorities(claims);
        var authentication = new JwtAuthenticationToken(userId, email, authorities);
        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    /**
     * Extracts PBAC powers from the JWT {@code powers} claim (string array) and maps them
     * to {@link GrantedAuthority} instances. Returns an empty list if the claim is absent.
     */
    @SuppressWarnings("unchecked")
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
