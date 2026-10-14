package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.RefreshToken;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface RefreshTokenRepository {

    Mono<RefreshToken> findByTokenHash(String tokenHash);

    Mono<RefreshToken> insert(RefreshToken token);

    /** Atomically revokes a non-revoked token. Emits {@code true} only for the caller that revoked it. */
    Mono<Boolean> revokeIfActive(UUID id);

    /** Whether the session still has a token that can renew it (not revoked, not expired). */
    Mono<Boolean> hasActiveToken(UUID sessionId);

    /** Ends a session: revokes every token of its family. */
    Mono<Void> revokeBySessionId(UUID sessionId);

    /** Ends every session of the account except {@code keptSessionId}. Emits the number of revoked tokens. */
    Mono<Long> revokeByUserIdExceptSession(UUID userId, UUID keptSessionId);

    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    Mono<Long> countActiveByPasskeyId(UUID passkeyId);
}
