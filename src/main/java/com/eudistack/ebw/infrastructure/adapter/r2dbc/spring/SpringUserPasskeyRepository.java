package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.UserPasskeyEntity;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringUserPasskeyRepository extends ReactiveCrudRepository<UserPasskeyEntity, UUID> {

    @Query("SELECT * FROM user_passkey WHERE user_id = :userId ORDER BY last_used_at DESC NULLS LAST, created_at DESC")
    Flux<UserPasskeyEntity> findByUserId(UUID userId);

    Mono<UserPasskeyEntity> findByIdAndUserId(UUID id, UUID userId);

    Mono<UserPasskeyEntity> findByUserIdAndCredentialId(UUID userId, String credentialId);

    Mono<Long> countByUserId(UUID userId);

    @Modifying
    @Query("UPDATE user_passkey SET last_used_at = NOW() WHERE id = :id")
    Mono<Void> touchLastUsed(UUID id);
}
