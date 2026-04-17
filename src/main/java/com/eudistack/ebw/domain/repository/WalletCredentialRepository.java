package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface WalletCredentialRepository {

    Mono<WalletCredential> save(WalletCredential credential);

    Mono<WalletCredential> findByIdAndUserId(UUID id, UUID userId);

    Flux<WalletCredential> findAllByUserId(UUID userId);

    Flux<WalletCredential> findAllByUserIdAndFilters(UUID userId, CredentialStatus status,
                                                      String credentialConfigId, String issuer);

    Mono<Void> deleteById(UUID id);
}
