package com.eudistack.ebw.integration;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.infrastructure.adapter.ratelimit.R2dbcIpRateLimiter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The per-IP counter against a real PostgreSQL: the single upsert must not lose hits when many requests land at
 * once, which is what several EBW tasks sharing one table do.
 */
class R2dbcIpRateLimiterIT extends IntegrationTestBase {

    @Autowired
    private IpRateLimiter rateLimiter;

    @Autowired
    private DatabaseClient databaseClient;

    @Autowired
    private RateLimitProperties properties;

    @Autowired
    private MeterRegistry meterRegistry;

    @Nested
    @DisplayName("check")
    class Check {

        @Test
        void check_requestsOverTheLimit_failWithRateLimitExceeded() {
            // Arrange
            var key = "register:ip:" + System.nanoTime();
            StepVerifier.create(rateLimiter.check(key, 2)).verifyComplete();
            StepVerifier.create(rateLimiter.check(key, 2)).verifyComplete();

            // Act
            var third = rateLimiter.check(key, 2);

            // Assert
            StepVerifier.create(third).expectError(RateLimitExceededException.class).verify();
        }

        @Test
        void check_differentKeys_areCountedSeparately() {
            // Arrange
            var suffix = System.nanoTime();
            StepVerifier.create(rateLimiter.check("register:ip:a" + suffix, 1)).verifyComplete();

            // Act
            var otherKey = rateLimiter.check("register:ip:b" + suffix, 1);

            // Assert
            StepVerifier.create(otherKey).verifyComplete();
        }

        @Test
        void check_concurrentRequests_letExactlyTheLimitThrough() {
            // Arrange
            var key = "register:ip:" + System.nanoTime();

            // Act
            var outcomes = Flux.range(0, 20)
                    .flatMap(i -> rateLimiter.check(key, 10).materialize(), 20)
                    .collectList()
                    .block(Duration.ofSeconds(30));

            // Assert
            assertThat(outcomes).hasSize(20);
            assertThat(outcomes.stream().filter(signal -> signal.isOnComplete()).count()).isEqualTo(10);
            assertThat(outcomes.stream().filter(signal -> signal.isOnError()).count()).isEqualTo(10);
            assertThat(query("SELECT hits FROM public.ip_rate_limit WHERE rate_key = '" + key + "'"))
                    .singleElement()
                    .satisfies(row -> assertThat((Integer) row.get("hits")).isBetween(11, 20));
        }

        @Test
        void check_twoInstancesSharingTheDatabase_letExactlyTheLimitThrough() {
            // Arrange — a second, independent limiter, as a second EBW task would have: its own memory, the same table
            var key = "register:ip:" + System.nanoTime();
            var otherInstance = new R2dbcIpRateLimiter(databaseClient, properties, meterRegistry);

            // Act — 11 requests alternated between both: neither instance alone goes over the limit of 10
            var outcomes = Flux.range(0, 11)
                    .concatMap(i -> (i % 2 == 0 ? rateLimiter : otherInstance).check(key, 10).materialize())
                    .collectList()
                    .block(Duration.ofSeconds(30));

            // Assert
            assertThat(outcomes).hasSize(11);
            assertThat(outcomes.stream().filter(signal -> signal.isOnComplete()).count()).isEqualTo(10);
            assertThat(outcomes.get(10).isOnError()).isTrue();
            StepVerifier.create(otherInstance.check(key, 10)).expectError(RateLimitExceededException.class).verify();
        }

        @Test
        void check_keyOverTheLimit_isRejectedWithoutWritingTheRowAgain() {
            // Arrange
            var key = "register:ip:" + System.nanoTime();
            StepVerifier.create(rateLimiter.check(key, 1)).verifyComplete();
            StepVerifier.create(rateLimiter.check(key, 1)).expectError(RateLimitExceededException.class).verify();

            // Act
            StepVerifier.create(rateLimiter.check(key, 1)).expectError(RateLimitExceededException.class).verify();
            StepVerifier.create(rateLimiter.check(key, 1)).expectError(RateLimitExceededException.class).verify();

            // Assert
            assertThat(query("SELECT hits FROM public.ip_rate_limit WHERE rate_key = '" + key + "'"))
                    .singleElement()
                    .satisfies(row -> assertThat(row.get("hits")).isEqualTo(2));
        }

        @Test
        void check_afterTheWindowHasPassed_startsANewWindow() {
            // Arrange
            var key = "register:ip:" + System.nanoTime();
            StepVerifier.create(rateLimiter.check(key, 2)).verifyComplete();
            StepVerifier.create(rateLimiter.check(key, 2)).verifyComplete();
            sql("UPDATE public.ip_rate_limit SET expires_at = now() - interval '1 second' WHERE rate_key = '"
                    + key + "'");

            // Act
            var afterExpiry = rateLimiter.check(key, 2);

            // Assert
            StepVerifier.create(afterExpiry).verifyComplete();
        }
    }

    @Nested
    @DisplayName("deleteExpired")
    class DeleteExpired {

        @Test
        void deleteExpired_mixOfLapsedAndActiveCounters_removesOnlyTheLapsedOnes() {
            // Arrange
            var suffix = System.nanoTime();
            var lapsed = "register:ip:lapsed" + suffix;
            var active = "register:ip:active" + suffix;
            StepVerifier.create(rateLimiter.check(lapsed, 5)).verifyComplete();
            StepVerifier.create(rateLimiter.check(active, 5)).verifyComplete();
            sql("UPDATE public.ip_rate_limit SET expires_at = now() - interval '1 second' WHERE rate_key = '"
                    + lapsed + "'");

            // Act
            var deleted = rateLimiter.deleteExpired();

            // Assert
            StepVerifier.create(deleted).expectNext(1L).verifyComplete();
            assertThat(query("SELECT rate_key FROM public.ip_rate_limit"))
                    .extracting(row -> row.get("rate_key"))
                    .containsExactly(active);
        }
    }
}
