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

    Mono<UserPasskeyEntity> findByCredentialId(String credentialId);

    Mono<Long> countByUserId(UUID userId);

    @Modifying
    @Query("UPDATE user_passkey SET display_name = :displayName WHERE id = :id")
    Mono<Long> updateDisplayName(UUID id, String displayName);

    /** Counter-based passkey: only applies if the stored counter is lower (no concurrent reuse). */
    @Modifying
    @Query("""
            UPDATE user_passkey
               SET sign_count = :signCount, backup_state = :backupState,
                   uv_initialized = (uv_initialized OR :userVerified), last_used_at = NOW()
             WHERE id = :id AND sign_count < :signCount
            """)
    Mono<Long> recordCountedAuthentication(UUID id, long signCount, boolean backupState, boolean userVerified);

    /** Passkey without counter (always 0, usual for synced passkeys). */
    @Modifying
    @Query("""
            UPDATE user_passkey
               SET backup_state = :backupState,
                   uv_initialized = (uv_initialized OR :userVerified), last_used_at = NOW()
             WHERE id = :id AND sign_count = 0
            """)
    Mono<Long> recordUncountedAuthentication(UUID id, boolean backupState, boolean userVerified);

    @Modifying
    @Query("UPDATE user_passkey SET last_used_at = NOW() WHERE id = :id")
    Mono<Void> touchLastUsed(UUID id);
}
