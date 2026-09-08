package com.eudistack.ebw.infrastructure.adapter.ratelimit;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.time.Duration;

class CaffeineEmailRateLimiterTest {

    private static final String EMAIL = "user@example.com";

    private CaffeineEmailRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        var properties = new RateLimitProperties(2, 10, 2, 20, 60, 20, 30, Duration.ofHours(1));
        rateLimiter = new CaffeineEmailRateLimiter(properties);
    }

    @Test
    void resetForEmail_afterBudgetExhausted_allowsRegisteringAgain() {
        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();
        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();
        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL))
                .expectError(RateLimitExceededException.class)
                .verify();

        StepVerifier.create(rateLimiter.resetForEmail(EMAIL)).verifyComplete();

        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();
    }

    @Test
    void resetForEmail_clearsTheVerifyCounterAsWell() {
        StepVerifier.create(rateLimiter.checkVerifyRate(EMAIL)).verifyComplete();
        StepVerifier.create(rateLimiter.checkVerifyRate(EMAIL)).verifyComplete();
        StepVerifier.create(rateLimiter.checkVerifyRate(EMAIL))
                .expectError(RateLimitExceededException.class)
                .verify();

        StepVerifier.create(rateLimiter.resetForEmail(EMAIL)).verifyComplete();

        StepVerifier.create(rateLimiter.checkVerifyRate(EMAIL)).verifyComplete();
    }

    @Test
    void resetForEmail_isCaseInsensitive_matchingTheCheckMethods() {
        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();
        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();

        StepVerifier.create(rateLimiter.resetForEmail("USER@EXAMPLE.COM")).verifyComplete();

        StepVerifier.create(rateLimiter.checkRegisterRate(EMAIL)).verifyComplete();
    }

    @Test
    void resetForEmail_leavesOtherEmailsUntouched() {
        var other = "other@example.com";
        StepVerifier.create(rateLimiter.checkRegisterRate(other)).verifyComplete();
        StepVerifier.create(rateLimiter.checkRegisterRate(other)).verifyComplete();

        StepVerifier.create(rateLimiter.resetForEmail(EMAIL)).verifyComplete();

        StepVerifier.create(rateLimiter.checkRegisterRate(other))
                .expectError(RateLimitExceededException.class)
                .verify();
    }

    @Test
    void resetForEmail_unknownEmail_completesWithoutError() {
        StepVerifier.create(rateLimiter.resetForEmail("never-seen@example.com")).verifyComplete();
    }
}
