package com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.keymanager.infrastructure.adapter.r2dbc.entity.HolderKeyEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

public interface SpringHolderKeyRepository extends ReactiveCrudRepository<HolderKeyEntity, String> {

    Mono<HolderKeyEntity> findFirstByHolderIdAndCredentialIdAndRevokedAtIsNull(
            String holderId, String credentialId);
}