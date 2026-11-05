package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.spi.IpRateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IpRateLimitHousekeepingJobTest {

    private IpRateLimiter ipRateLimiter;
    private IpRateLimitHousekeepingJob job;

    @BeforeEach
    void setUp() {
        ipRateLimiter = mock(IpRateLimiter.class);
        job = new IpRateLimitHousekeepingJob(ipRateLimiter);
    }

    @Test
    void cleanup_lapsedCounters_emitsTheNumberOfDeletedRows() {
        // Arrange
        when(ipRateLimiter.deleteExpired()).thenReturn(Mono.just(7L));

        // Act
        var result = job.cleanup();

        // Assert
        StepVerifier.create(result).expectNext(7L).verifyComplete();
    }

    @Test
    void cleanup_deletionFails_emitsZeroInsteadOfFailing() {
        // Arrange
        when(ipRateLimiter.deleteExpired()).thenReturn(Mono.error(new IllegalStateException("db down")));

        // Act
        var result = job.cleanup();

        // Assert
        StepVerifier.create(result).expectNext(0L).verifyComplete();
    }
}
