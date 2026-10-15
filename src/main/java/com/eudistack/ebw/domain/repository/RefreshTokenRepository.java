package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.RefreshToken;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface RefreshTokenRepository {

    Mono<RefreshToken> findByTokenHash(String tokenHash);

    Mono<RefreshToken> insert(RefreshToken token);

    Mono<Void> deleteById(UUID id);

    /** Atomically revokes a non-revoked token. Emits {@code true} only for the caller that revoked it. */
    Mono<Boolean> revokeIfActive(UUID id);

    /** Whether the session still has a token that can renew it (not revoked, not expired). */
    Mono<Boolean> hasActiveToken(UUID sessionId);

    /**
     * Ends a session: revokes every token of its family. Emits the number of tokens this call
     * revoked, {@code 0} when the session was already ended.
     */
    Mono<Long> revokeBySessionId(UUID sessionId);

    /**
     * Closes the sessions that lapsed without being ended: no token can renew them any more and
     * the last one is expired but not revoked. Revokes their tokens in one conditional statement
     * and emits each closed session once, only to the caller whose statement revoked it.
     */
    Flux<ExpiredSession> expireLapsedSessions();

    /** Ends every session of the account except {@code keptSessionId}. Emits the number of revoked tokens. */
    Mono<Long> revokeByUserIdExceptSession(UUID userId, UUID keptSessionId);

    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    Mono<Long> countActiveByPasskeyId(UUID passkeyId);

    /**
     * Deletes the tokens of the sessions that ended before {@code cutoff}: every token revoked or
     * expired, and none valid after the cutoff. Emits the number of deleted rows.
     */
    Mono<Long> deleteSessionsEndedBefore(java.time.Instant cutoff);
}
