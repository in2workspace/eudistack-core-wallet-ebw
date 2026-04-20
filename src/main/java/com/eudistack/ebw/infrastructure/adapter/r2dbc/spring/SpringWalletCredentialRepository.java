package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringWalletCredentialRepository extends ReactiveCrudRepository<WalletCredentialEntity, UUID> {

    @Query("""
            SELECT id, user_id, format, credential_config_id, kid, credential_type, vct,
                   issuer, subject, issuance_date, expiration_date, status, issuer_metadata,
                   created_at, updated_at
            FROM wallet_credential WHERE user_id = :userId
            """)
    Flux<WalletCredentialEntity> findAllByUserIdWithoutRaw(UUID userId);

    /**
     * List credentials for a user, optionally filtered by status, credential configuration id,
     * and issuer. Nullable filter parameters are ignored via {@code (:param IS NULL OR column = :param)}
     * predicates. The {@code credential_raw} column is intentionally omitted from the projection
     * because the list endpoint never returns it (EUDI-040 review W2).
     */
    @Query("""
            SELECT id, user_id, format, credential_config_id, kid, credential_type, vct,
                   issuer, subject, issuance_date, expiration_date, status, issuer_metadata,
                   created_at, updated_at
            FROM wallet_credential
            WHERE user_id = :userId
              AND (:status IS NULL OR status = :status)
              AND (:credentialConfigId IS NULL OR credential_config_id = :credentialConfigId)
              AND (:issuer IS NULL OR issuer = :issuer)
            """)
    Flux<WalletCredentialEntity> findAllByUserIdAndFiltersWithoutRaw(UUID userId,
                                                                     String status,
                                                                     String credentialConfigId,
                                                                     String issuer);

    Mono<WalletCredentialEntity> findByIdAndUserId(UUID id, UUID userId);
}
