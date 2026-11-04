package com.eudistack.ebw.support;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Counts hits in memory, without expiry: enough for tests that exercise the callers of {@link IpRateLimiter}. */
public final class InMemoryIpRateLimiter implements IpRateLimiter {

    private final Duration window;
    private final Map<String, Integer> hits = new ConcurrentHashMap<>();

    public InMemoryIpRateLimiter(Duration window) {
        this.window = window;
    }

    @Override
    public Mono<Void> check(String key, int limit) {
        return hits.merge(key, 1, Integer::sum) > limit
                ? Mono.error(new RateLimitExceededException(window.toSeconds()))
                : Mono.empty();
    }

    @Override
    public Mono<Long> deleteExpired() {
        return Mono.just(0L);
    }
}
