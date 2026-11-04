package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

/**
 * Per-IP rate limiting port. The counters are shared by every running instance, so the configured
 * limit holds however many instances serve the traffic.
 */
public interface IpRateLimiter {

    /** Counts one request under {@code key}; fails with RateLimitExceededException once {@code limit} is passed. */
    Mono<Void> check(String key, int limit);

    /** Emits the number of lapsed counters removed. */
    Mono<Long> deleteExpired();
}
