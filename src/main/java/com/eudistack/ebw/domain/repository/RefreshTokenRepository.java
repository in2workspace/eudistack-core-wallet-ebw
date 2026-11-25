package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.ExpiredSession;
import com.eudistack.ebw.domain.model.PendingPasskeyNotice;
import com.eudistack.ebw.domain.model.RefreshToken;
import com.eudistack.ebw.domain.model.SessionState;
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

    /** Ends every session of the account, on any device ("it was not me", EUD-315). Emits the revoked tokens. */
    Mono<Long> revokeByUserId(UUID userId);

    /**
     * Whether the session is alive and the active Wallet Instance it is bound to, in one query (EUD-15 AD-2).
     * A token of the family that a rotation stored without the binding does not hide the one that has it.
     */
    Mono<SessionState> findSessionState(UUID sessionId);

    /**
     * Binds every token of the session, the rotated ones too, to the instance (EUD-15 design §2.1). Emits the
     * updated rows.
     */
    Mono<Long> bindSession(UUID sessionId, UUID walletInstanceId);

    /**
     * Ends every session bound to the instance: all the tokens of every family with a token bound to it, so a
     * token a concurrent rotation stored without the binding is revoked too. Emits each session ended.
     */
    Flux<UUID> revokeByWalletInstanceId(UUID walletInstanceId);

    /**
     * Copies to a token just stored by a rotation the session state of the token it replaced, as that one is now:
     * a binding or a cleared notice that landed during the rotation is not lost.
     */
    Mono<Void> inheritSessionState(UUID newTokenId, UUID previousTokenId);

    /** Marks the session as owing the new-passkey email (EUD-8 AD-11). */
    Mono<Void> markPasskeyNoticePending(UUID sessionId);

    /**
     * Clears the mark of the session. Emits {@code true} only for the call that cleared it, so the email is
     * sent once.
     */
    Mono<Boolean> clearPasskeyNoticePending(UUID sessionId);

    /**
     * Clears the mark of the sessions that are no longer alive (ended, expired by inactivity or by maximum
     * duration) and emits each one once, to the caller whose statement cleared it.
     */
    Flux<PendingPasskeyNotice> takePendingNoticesOfEndedSessions();

    /**
     * Deletes the tokens of the sessions that ended before {@code cutoff}: every token revoked or
     * expired, and none valid after the cutoff. Emits the number of deleted rows.
     */
    Mono<Long> deleteSessionsEndedBefore(java.time.Instant cutoff);
}
