package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletCredentialEntity;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringWalletCredentialRepository extends ReactiveCrudRepository<WalletCredentialEntity, UUID> {

    @Query("""
            SELECT id, user_id, credential_raw, format, credential_config_id, kid, credential_type, vct,
                   issuer, subject, issuance_date, expiration_date, status, issuer_metadata,
                   created_at, updated_at
            FROM wallet_credential WHERE user_id = :userId
            """)
    Flux<WalletCredentialEntity> findAllByUserId(UUID userId);

    @Query("""
            SELECT id, user_id, credential_raw, format, credential_config_id, kid, credential_type, vct,
                   issuer, subject, issuance_date, expiration_date, status, issuer_metadata,
                   created_at, updated_at
            FROM wallet_credential
            WHERE user_id = :userId
              AND (:status IS NULL OR status = :status)
              AND (:credentialConfigId IS NULL OR credential_config_id = :credentialConfigId)
              AND (:issuer IS NULL OR issuer = :issuer)
            """)
    Flux<WalletCredentialEntity> findAllByUserIdAndFilters(UUID userId,
                                                           String status,
                                                           String credentialConfigId,
                                                           String issuer);

    Mono<WalletCredentialEntity> findByIdAndUserId(UUID id, UUID userId);
}
