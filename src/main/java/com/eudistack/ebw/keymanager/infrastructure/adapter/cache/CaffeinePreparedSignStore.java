package com.eudistack.ebw.keymanager.infrastructure.adapter.cache;

import com.eudistack.ebw.keymanager.application.PreparedSign;
import com.eudistack.ebw.keymanager.application.PreparedSignStore;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Optional;

/**
 * In-process Caffeine implementation of {@link PreparedSignStore}.
 *
 * <p>Entries expire {@value TTL_MINUTES} minutes after write, matching the {@code correlation_id}
 * TTL specified in architecture.md §8.1. {@code Caffeine} eviction is time-based (wall-clock),
 * so no background thread is needed for TTL enforcement.</p>
 *
 * <p><b>Single-instance caveat:</b> this store is process-local. Running multiple EBW instances
 * will result in a {@code prepareSign} on instance A and a {@code submitSignedAssertion} on
 * instance B missing the prepared session. Before enabling horizontal scaling (EUDISTACK-68),
 * replace this adapter with a Redis-backed implementation.
 * See Tech Debt ticket: [EUDISTACK-TBD] Shared correlation store for hybrid sign handshake.
 * </p>
 *
 * <p>Spec: EUDISTACK-536 EC-03; architecture.md §8.1.</p>
 */
public class CaffeinePreparedSignStore implements PreparedSignStore {

    static final int TTL_MINUTES = 5;
    static final long MAX_SIZE = 100_000;

    private final Cache<String, PreparedSign> cache;

    public CaffeinePreparedSignStore() {
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(TTL_MINUTES))
                .maximumSize(MAX_SIZE)
                .build();
    }

    /** Package-private constructor for testing with a pre-configured cache. */
    CaffeinePreparedSignStore(Cache<String, PreparedSign> cache) {
        this.cache = cache;
    }

    /**
     * Stores a pending session. No-op (putIfAbsent semantics) if the {@code correlationId}
     * already has a live entry — handles network retries of {@code prepareSign} (EC-03).
     */
    @Override
    public Mono<Void> putPending(String correlationId, PreparedSign prepared) {
        return Mono.fromRunnable(() ->
                cache.asMap().putIfAbsent(correlationId, prepared));
    }

    @Override
    public Mono<Optional<PreparedSign>> getIfPresent(String correlationId) {
        return Mono.fromCallable(() ->
                Optional.ofNullable(cache.getIfPresent(correlationId)));
    }

    /**
     * Atomically sets {@code resolvedKbJwt} on the existing entry.
     * If the entry is already resolved the existing value is preserved (idempotent replay).
     * If the entry has expired this is a no-op (the subsequent {@code SubmitSignedUseCase}
     * look-up will see an empty Optional and throw {@code InvalidSignatureSubmissionException}).
     */
    @Override
    public Mono<Void> markResolved(String correlationId, String kbJwt) {
        return Mono.fromRunnable(() ->
                cache.asMap().computeIfPresent(correlationId, (key, existing) ->
                        existing.isPending() ? existing.withResolved(kbJwt) : existing));
    }
}
