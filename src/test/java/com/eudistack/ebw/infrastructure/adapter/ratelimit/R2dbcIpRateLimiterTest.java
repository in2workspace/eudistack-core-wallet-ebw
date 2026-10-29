package com.eudistack.ebw.infrastructure.adapter.ratelimit;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.DatabaseClientStub;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link R2dbcIpRateLimiter} — the limit decision on the counter the database returns, the memory of
 * blocked keys and the fail-open policy. The atomic upsert itself runs against PostgreSQL in
 * {@code R2dbcIpRateLimiterIT}.
 */
class R2dbcIpRateLimiterTest {

    private static final RateLimitProperties PROPERTIES =
            new RateLimitProperties(3, 10, 10, 20, 60, 20, 60, 30, 2, Duration.ofHours(1));

    private DatabaseClientStub db;
    private SimpleMeterRegistry meterRegistry;
    private R2dbcIpRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        db = new DatabaseClientStub();
        meterRegistry = new SimpleMeterRegistry();
        rateLimiter = new R2dbcIpRateLimiter(db.client, PROPERTIES, meterRegistry);
    }

    @Nested
    @DisplayName("check")
    class Check {

        @Test
        void check_counterWithinTheLimit_completes() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(10);

            // Act
            var result = rateLimiter.check("register:ip:203.0.113.7", 10);

            // Assert
            StepVerifier.create(result).verifyComplete();
        }

        @Test
        void check_counterOverTheLimit_failsWithTheWindowAsRetryAfter() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(11);

            // Act
            var result = rateLimiter.check("register:ip:203.0.113.7", 10);

            // Assert
            StepVerifier.create(result)
                    .expectErrorSatisfies(error -> assertThat(error)
                            .isInstanceOf(RateLimitExceededException.class)
                            .extracting(e -> ((RateLimitExceededException) e).getRetryAfterSeconds())
                            .isEqualTo(3600L))
                    .verify();
        }

        @Test
        void check_anyRequest_bindsTheKeyAndTheWindowInSeconds() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(1);

            // Act
            StepVerifier.create(rateLimiter.check("verify:ip:198.51.100.4", 5)).verifyComplete();

            // Assert
            assertThat(db.bindings)
                    .containsEntry("rateKey", "verify:ip:198.51.100.4")
                    .containsEntry("windowSeconds", 3600.0);
            assertThat(db.executedSql).singleElement().asString().contains("public.ip_rate_limit");
        }

        @Test
        void check_databaseFailure_letsTheRequestThroughAndCountsTheError() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenThrow(new IllegalStateException("connection refused"));

            // Act
            var result = rateLimiter.check("register:ip:203.0.113.7", 10);

            // Assert
            StepVerifier.create(result).verifyComplete();
            assertThat(meterRegistry.counter(R2dbcIpRateLimiter.STORE_ERRORS_METRIC).count()).isEqualTo(1.0);
        }

        @Test
        void check_everyDatabaseFailure_isCounted() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenThrow(new IllegalStateException("connection refused"));

            // Act
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10)).verifyComplete();
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10)).verifyComplete();

            // Assert
            assertThat(meterRegistry.counter(R2dbcIpRateLimiter.STORE_ERRORS_METRIC).count()).isEqualTo(2.0);
        }

        @Test
        void check_counterOverTheLimit_doesNotCountAStoreError() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(11);

            // Act
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10))
                    .expectError(RateLimitExceededException.class)
                    .verify();

            // Assert
            assertThat(meterRegistry.counter(R2dbcIpRateLimiter.STORE_ERRORS_METRIC).count()).isZero();
        }
    }

    @Nested
    @DisplayName("blocked keys")
    class BlockedKeys {

        @Test
        void check_keyAlreadyFoundOverTheLimit_failsWithoutQueryingTheDatabaseAgain() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(11);
            when(db.row.get("remaining_seconds", Double.class)).thenReturn(1800.0);
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10))
                    .expectError(RateLimitExceededException.class)
                    .verify();

            // Act
            var second = rateLimiter.check("register:ip:203.0.113.7", 10);

            // Assert
            StepVerifier.create(second).expectError(RateLimitExceededException.class).verify();
            assertThat(db.executedSql).hasSize(1);
        }

        @Test
        void check_otherKeyWhileOneIsBlocked_stillQueriesTheDatabase() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(11, 1);
            when(db.row.get("remaining_seconds", Double.class)).thenReturn(1800.0);
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10))
                    .expectError(RateLimitExceededException.class)
                    .verify();

            // Act
            var otherKey = rateLimiter.check("register:ip:203.0.113.8", 10);

            // Assert
            StepVerifier.create(otherKey).verifyComplete();
            assertThat(db.executedSql).hasSize(2);
        }

        @Test
        void check_overTheLimitWithNoTimeLeft_isNotRemembered() {
            // Arrange
            when(db.row.get("hits", Integer.class)).thenReturn(11);
            when(db.row.get("remaining_seconds", Double.class)).thenReturn(0.0);
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10))
                    .expectError(RateLimitExceededException.class)
                    .verify();

            // Act
            StepVerifier.create(rateLimiter.check("register:ip:203.0.113.7", 10))
                    .expectError(RateLimitExceededException.class)
                    .verify();

            // Assert
            assertThat(db.executedSql).hasSize(2);
        }
    }

    @Nested
    @DisplayName("deleteExpired")
    class DeleteExpired {

        @Test
        void deleteExpired_lapsedCounters_emitsTheNumberOfDeletedRows() {
            // Arrange
            db.rowsUpdated = Mono.just(4L);

            // Act
            var result = rateLimiter.deleteExpired();

            // Assert
            StepVerifier.create(result).expectNext(4L).verifyComplete();
            assertThat(db.executedSql).singleElement().asString().contains("DELETE FROM public.ip_rate_limit");
        }
    }
}
