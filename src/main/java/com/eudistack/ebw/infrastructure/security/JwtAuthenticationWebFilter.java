package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtAuthenticationWebFilter implements WebFilter {

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
                .flatMap(claims -> {
                    var userId = UUID.fromString((String) claims.get("sub"));
                    var email = (String) claims.get("email");
                    var authentication = new JwtAuthenticationToken(userId, email, extractAuthorities(claims));
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                })
                .onErrorResume(InvalidTokenException.class, e -> chain.filter(exchange));
    }

    /**
     * Maps the OAuth2-style {@code scope} (space-delimited string) or {@code scp} (string array)
     * JWT claim, if present, to {@code SCOPE_<value>} granted authorities (Spring convention).
     *
     * <p>EBW user tokens carry neither claim, so this returns an empty list for them — they keep
     * authenticating with zero authorities exactly as before (SEC-B2: purely additive change).
     */
    private static Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        Object scope = claims.get("scope");
        if (scope instanceof String s && !s.isBlank()) {
            for (String value : s.trim().split("\\s+")) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + value));
            }
        }
        Object scp = claims.get("scp");
        if (scp instanceof Collection<?> values) {
            for (Object value : values) {
                if (value != null) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + value));
                }
            }
        }
        return authorities;
    }
}
