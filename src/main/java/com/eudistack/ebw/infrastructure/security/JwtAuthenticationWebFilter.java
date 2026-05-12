package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

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
                    var authentication = new JwtAuthenticationToken(userId, email);
                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                })
                .onErrorResume(InvalidTokenException.class, e -> chain.filter(exchange));
    }
}
