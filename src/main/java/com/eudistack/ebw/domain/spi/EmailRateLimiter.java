package com.eudistack.ebw.domain.spi;

import reactor.core.publisher.Mono;

/**
 * Per-email rate limiting port. Implementations track request counts per email
 * and throw RateLimitExceededException when limits are exceeded.
 */
public interface EmailRateLimiter {

    Mono<Void> checkRegisterRate(String email);

    Mono<Void> checkVerifyRate(String email);
}
