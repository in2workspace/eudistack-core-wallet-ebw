package com.eudistack.ebw.infrastructure.adapter.ratelimit;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicInteger;

@Component
public class CaffeineEmailRateLimiter implements EmailRateLimiter {

    private final RateLimitProperties properties;
    private final Cache<String, AtomicInteger> cache;

    public CaffeineEmailRateLimiter(RateLimitProperties properties) {
        this.properties = properties;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(properties.window())
                .maximumSize(100_000)
                .build();
    }

    @Override
    public Mono<Void> checkRegisterRate(String email) {
        return check("register:email:" + email.toLowerCase(), properties.registerPerEmail());
    }

    @Override
    public Mono<Void> checkVerifyRate(String email) {
        return check("verify:email:" + email.toLowerCase(), properties.verifyPerEmail());
    }

    private Mono<Void> check(String key, int limit) {
        var counter = cache.get(key, k -> new AtomicInteger(0));
        if (counter.incrementAndGet() > limit) {
            var retryAfter = properties.window().toSeconds();
            return Mono.error(new RateLimitExceededException(retryAfter));
        }
        return Mono.empty();
    }
}
