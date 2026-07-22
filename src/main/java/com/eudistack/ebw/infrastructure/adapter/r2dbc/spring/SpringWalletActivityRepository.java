package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletActivityEntity;
import io.r2dbc.postgresql.codec.Json;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface SpringWalletActivityRepository extends ReactiveCrudRepository<WalletActivityEntity, UUID> {

    /**
     * Emits the inserted row, or completes empty when a row with the same id already
     * exists (ON CONFLICT DO NOTHING) — backs the idempotent sync semantics of
     * {@link com.eudistack.ebw.domain.repository.WalletActivityRepository#insertIfAbsent}.
     */
    @Query("""
            INSERT INTO wallet_activity (id, user_id, type, credential_name, counterparty, details, shared_attributes, created_at)
            VALUES (:id, :userId, :type, :credentialName, :counterparty, :details, :sharedAttributes, :createdAt)
            ON CONFLICT (id) DO NOTHING
            RETURNING id, user_id, type, credential_name, counterparty, details, shared_attributes, created_at
            """)
    Mono<WalletActivityEntity> insertIfAbsent(UUID id, UUID userId, String type, String credentialName,
                                               String counterparty, String details, Json sharedAttributes,
                                               Instant createdAt);

    @Query("""
            SELECT id, user_id, type, credential_name, counterparty, details, shared_attributes, created_at
            FROM wallet_activity
            WHERE user_id = :userId
            ORDER BY created_at DESC
            LIMIT :limit
            """)
    Flux<WalletActivityEntity> findRecentByUserId(UUID userId, int limit);
}
