package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.spi.IpRateLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Every ten minutes, removes the per-IP counters whose window has passed, so the table only holds the clients
 * seen in the current window.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IpRateLimitHousekeepingJob {

    private final IpRateLimiter ipRateLimiter;

    @Scheduled(cron = "0 */10 * * * *")
    public void scheduledCleanup() {
        cleanup().subscribe();
    }

    /** Emits the number of deleted counters. */
    public Mono<Long> cleanup() {
        return ipRateLimiter.deleteExpired()
                .doOnNext(deleted -> log.debug("Deleted {} lapsed IP rate limit counters", deleted))
                .onErrorResume(e -> {
                    log.warn("IP rate limit housekeeping failed: {}", e.getMessage());
                    return Mono.just(0L);
                });
    }
}
