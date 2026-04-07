package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitWebFilter implements WebFilter, Ordered {

    private final RateLimitProperties properties;
    private final Cache<String, AtomicInteger> cache;

    public RateLimitWebFilter(RateLimitProperties properties) {
        this.properties = properties;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(properties.window())
                .maximumSize(100_000)
                .build();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var request = exchange.getRequest();
        if (!HttpMethod.POST.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        var path = request.getPath().value();
        var ip = resolveIp(exchange);

        return switch (path) {
            case "/api/v1/auth/register" -> checkRateLimit("register:ip:" + ip, properties.registerPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/verify-email" -> checkRateLimit("verify:ip:" + ip, properties.verifyPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/refresh" -> checkRateLimit("refresh:ip:" + ip, properties.refreshPerIp())
                    .then(chain.filter(exchange));
            case "/api/v1/auth/logout" -> checkRateLimit("logout:ip:" + ip, properties.logoutPerIp())
                    .then(chain.filter(exchange));
            default -> chain.filter(exchange);
        };
    }

    private Mono<Void> checkRateLimit(String key, int limit) {
        var counter = cache.get(key, k -> new AtomicInteger(0));
        if (counter.incrementAndGet() > limit) {
            var retryAfter = properties.window().toSeconds();
            return Mono.error(new RateLimitExceededException(retryAfter));
        }
        return Mono.empty();
    }

    private String resolveIp(ServerWebExchange exchange) {
        var forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        var remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }
}
