package com.eudistack.ebw.infrastructure.adapter.ratelimit;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.spi.IpRateLimiter;
import com.eudistack.ebw.infrastructure.adapter.properties.RateLimitProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@code public.ip_rate_limit} with {@link DatabaseClient}. The increment is a single atomic upsert, so
 * concurrent instances never lose a hit, and the window is measured with the database clock, not the
 * instance's. A key found over its limit is remembered in memory for the rest of its window, so a client that
 * keeps sending after being blocked costs no more database writes. A database failure lets the request
 * through, logged and counted in {@value #STORE_ERRORS_METRIC}: the limit must not take sign-up down with it.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class R2dbcIpRateLimiter implements IpRateLimiter {

    public static final String STORE_ERRORS_METRIC = "ip_rate_limit_store_errors_total";

    private static final int MAX_BLOCKED_KEYS = 100_000;
    private static final long ERROR_LOG_INTERVAL_NANOS = Duration.ofMinutes(1).toNanos();

    private static final String HIT_SQL = """
            INSERT INTO public.ip_rate_limit AS counter (rate_key, hits, expires_at)
            VALUES (:rateKey, 1, now() + make_interval(secs => :windowSeconds))
            ON CONFLICT (rate_key) DO UPDATE SET
                hits = CASE WHEN counter.expires_at <= now() THEN 1 ELSE counter.hits + 1 END,
                expires_at = CASE WHEN counter.expires_at <= now() THEN EXCLUDED.expires_at
                                  ELSE counter.expires_at END
            RETURNING hits,
                CAST(EXTRACT(EPOCH FROM (expires_at - now())) AS double precision) AS remaining_seconds
            """;

    private static final String DELETE_EXPIRED_SQL = "DELETE FROM public.ip_rate_limit WHERE expires_at <= now()";

    private record Counter(Integer hits, Double remainingSeconds) {
    }

    private final DatabaseClient databaseClient;
    private final RateLimitProperties properties;
    private final MeterRegistry meterRegistry;

    // Value = time left in the window when the key was found over its limit; the entry expires with it.
    private final Cache<String, Duration> blockedKeys = Caffeine.newBuilder()
            .maximumSize(MAX_BLOCKED_KEYS)
            .expireAfter(Expiry.<String, Duration>creating((key, remaining) -> remaining))
            .build();
    private final AtomicLong lastErrorLogNanos = new AtomicLong(System.nanoTime() - ERROR_LOG_INTERVAL_NANOS);

    @Override
    public Mono<Void> check(String key, int limit) {
        var windowSeconds = properties.window().toSeconds();
        if (blockedKeys.getIfPresent(key) != null) {
            return Mono.error(new RateLimitExceededException(windowSeconds));
        }
        return databaseClient.sql(HIT_SQL)
                .bind("rateKey", key)
                .bind("windowSeconds", (double) windowSeconds)
                .map((row, metadata) -> new Counter(row.get("hits", Integer.class),
                        row.get("remaining_seconds", Double.class)))
                .one()
                .flatMap(counter -> counter.hits() > limit
                        ? block(key, counter, windowSeconds)
                        : Mono.<Void>empty())
                .onErrorResume(e -> !(e instanceof RateLimitExceededException), this::letThrough);
    }

    @Override
    public Mono<Long> deleteExpired() {
        return databaseClient.sql(DELETE_EXPIRED_SQL).fetch().rowsUpdated();
    }

    private Mono<Void> block(String key, Counter counter, long windowSeconds) {
        var remaining = counter.remainingSeconds();
        if (remaining != null && remaining > 0) {
            blockedKeys.put(key, Duration.ofMillis((long) (remaining * 1000)));
        }
        return Mono.error(new RateLimitExceededException(windowSeconds));
    }

    private Mono<Void> letThrough(Throwable error) {
        meterRegistry.counter(STORE_ERRORS_METRIC).increment();
        logStoreFailure(error);
        return Mono.empty();
    }

    /** One error line a minute: during an outage every request fails, and the metric already carries the rate. */
    private void logStoreFailure(Throwable error) {
        var now = System.nanoTime();
        var last = lastErrorLogNanos.get();
        if (now - last >= ERROR_LOG_INTERVAL_NANOS && lastErrorLogNanos.compareAndSet(last, now)) {
            log.error("IP rate limit counter unavailable, letting the requests through: {}", error.getMessage());
        } else {
            log.debug("IP rate limit counter unavailable, letting the request through: {}", error.getMessage());
        }
    }
}
