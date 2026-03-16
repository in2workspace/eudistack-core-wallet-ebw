package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletUserEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringWalletUserRepository extends ReactiveCrudRepository<WalletUserEntity, UUID> {

    Mono<WalletUserEntity> findByEmail(String email);
}
