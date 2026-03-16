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
    @Query("UPDATE refresh_token SET revoked = true WHERE passkey_id = $1 AND revoked = false")
    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    @Modifying
    @Query("UPDATE refresh_token SET revoked = true WHERE user_id = $1 AND revoked = false")
    Mono<Void> revokeByUserId(UUID userId);

    @Query("SELECT COUNT(*) FROM refresh_token WHERE passkey_id = $1 AND revoked = false AND expires_at > NOW()")
    Mono<Long> countActiveByPasskeyId(UUID passkeyId);
}
