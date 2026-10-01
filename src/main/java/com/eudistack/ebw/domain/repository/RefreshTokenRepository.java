package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.RefreshToken;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface RefreshTokenRepository {

    Mono<RefreshToken> findByTokenHash(String tokenHash);

    Mono<RefreshToken> findById(UUID id);

    Mono<RefreshToken> save(RefreshToken token);

    Mono<Void> revokeByPasskeyId(UUID passkeyId);

    Mono<Void> revokeByUserId(UUID userId);

    Mono<Void> revokeOrphanByUserId(UUID userId);

    Mono<Long> countActiveByPasskeyId(UUID passkeyId);

    Mono<Void> updatePasskeyIdByTokenHash(String tokenHash, UUID passkeyId);
}
