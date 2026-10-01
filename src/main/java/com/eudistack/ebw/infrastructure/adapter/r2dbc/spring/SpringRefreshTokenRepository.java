package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.RefreshTokenEntity;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringRefreshTokenRepository extends ReactiveCrudRepository<RefreshTokenEntity, UUID> {

    Mono<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE passkey_id = :passkeyId AND revoked = false")
    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE user_id = :userId AND revoked = false")
    Mono<Void> revokeByUserId(UUID userId);

    /**
     * Scoped to sessions never attributed to any device (mid email+OTP, before passkey
     * confirmation) — see AuthTokenService.rotateRefreshToken's reuse-detection. A
     * passkey_id of NULL here is not just "unconfirmed": it's also what a deleted
     * passkey leaves behind via refresh_token's ON DELETE SET NULL, so this must never
     * widen to every session for the user — only the still-unattributed ones.
     */
    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE user_id = :userId AND passkey_id IS NULL AND revoked = false")
    Mono<Void> revokeOrphanByUserId(UUID userId);

    @Query("SELECT COUNT(*) FROM refresh_token WHERE passkey_id = :passkeyId AND revoked = false AND expires_at > NOW()")
    Mono<Long> countActiveByPasskeyId(UUID passkeyId);

    @Modifying
    @Query("UPDATE refresh_token SET passkey_id = :passkeyId WHERE token_hash = :tokenHash AND revoked = false")
    Mono<Void> updatePasskeyIdByTokenHash(String tokenHash, UUID passkeyId);
}
