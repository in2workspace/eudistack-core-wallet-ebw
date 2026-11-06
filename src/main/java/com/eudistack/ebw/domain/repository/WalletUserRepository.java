package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.WalletUser;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface WalletUserRepository {

    Mono<WalletUser> findById(UUID id);

    Mono<WalletUser> findByEmail(String email);

    /**
     * Reads the account and locks its row until the end of the transaction, so two registrations
     * with onboarding tickets of the same account are serialized (EUD-315 decision P7).
     */
    Mono<WalletUser> lockById(UUID id);

    Mono<WalletUser> save(WalletUser user);
}
