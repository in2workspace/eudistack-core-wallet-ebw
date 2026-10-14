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
    @Query("UPDATE refresh_token SET revoked = true WHERE id = :id AND revoked = false")
    Mono<Long> revokeIfActive(UUID id);

    @Query("SELECT EXISTS (SELECT 1 FROM refresh_token "
            + "WHERE session_id = :sessionId AND revoked = false AND expires_at > NOW())")
    Mono<Boolean> hasActiveToken(UUID sessionId);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE session_id = :sessionId AND revoked = false")
    Mono<Long> revokeBySessionId(UUID sessionId);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true "
            + "WHERE user_id = :userId AND session_id <> :sessionId AND revoked = false")
    Mono<Long> revokeByUserIdExceptSession(UUID userId, UUID sessionId);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE passkey_id = :passkeyId AND revoked = false")
    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    @Query("SELECT COUNT(*) FROM refresh_token WHERE passkey_id = :passkeyId AND revoked = false AND expires_at > NOW()")
    Mono<Long> countActiveByPasskeyId(UUID passkeyId);
}
