package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.UUID;

/**
 * Bridges the stateless access-token JWT to the mutable revocation state that lives in
 * {@code refresh_token}. Without this, revoking a passkey/device/session only stopped
 * future refreshes — the access token already handed out kept being accepted until its
 * own {@code exp} (up to the full access-token TTL later), during which the "revoked"
 * device could still present/issue credentials.
 *
 * <p>{@link #isValid(UUID)} is backed by a short cache so a revoked session is rejected
 * within {@link #CACHE_TTL} instead of only at its next refresh, without a DB round trip
 * on every authenticated request. {@link #invalidateAll()} additionally clears it eagerly
 * on every revocation, so a session checked-as-valid moments earlier on this same
 * instance is rejected on its very next request rather than waiting out the TTL.
 * Cross-instance staleness (a different task in a multi-task deployment) stays bounded by
 * {@link #CACHE_TTL}.
 *
 * <p>KNOWN RISK (code review, fix/session-revocation-not-hot, 2026-10-05): {@link
 * #invalidateAll()} only clears THIS instance's cache. Only one EBW task is deployed
 * today, so that is the only cache there is and revocation is effectively immediate;
 * the moment a second task is deployed, the other task(s) can keep accepting a revoked
 * session for up to {@link #CACHE_TTL} until their own entry expires. There is also a
 * narrow race, bounded by the same {@link #CACHE_TTL}: an {@link #isValid(UUID)} that
 * read the DB just before a revoke's commit can {@code put(true)} just after that
 * revoke's {@link #invalidateAll()} already ran. Revisit this (per-{@code sessionId}
 * invalidation instead of clearing everything, or skipping the cache on the most
 * sensitive endpoints) before scaling EBW beyond one task.
 */
@RequiredArgsConstructor
public class SessionRevocationChecker {

    private static final Duration CACHE_TTL = Duration.ofSeconds(3);

    private final RefreshTokenRepository refreshTokenRepository;
    private final Cache<UUID, Boolean> validSessionCache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL)
            .maximumSize(50_000)
            .build();

    public Mono<Boolean> isValid(UUID sessionId) {
        var cached = validSessionCache.getIfPresent(sessionId);
        if (cached != null) {
            return Mono.just(cached);
        }
        return refreshTokenRepository.findById(sessionId)
                .map(token -> !token.isRevoked())
                .defaultIfEmpty(false)
                .doOnNext(valid -> validSessionCache.put(sessionId, valid));
    }

    public void invalidateAll() {
        validSessionCache.invalidateAll();
    }
}
