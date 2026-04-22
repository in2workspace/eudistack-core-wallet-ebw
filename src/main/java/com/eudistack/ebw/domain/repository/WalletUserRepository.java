package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.WalletUser;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface WalletUserRepository {

    Mono<WalletUser> findById(UUID id);

    Mono<WalletUser> findByEmail(String email);

    Mono<WalletUser> save(WalletUser user);
}
