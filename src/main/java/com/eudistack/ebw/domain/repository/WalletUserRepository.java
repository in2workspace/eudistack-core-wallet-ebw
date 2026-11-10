package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.WalletUser;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface WalletUserRepository {

    Mono<WalletUser> findById(UUID id);

    Mono<WalletUser> findByEmail(String email);

    /**
     * Every account whose email is {@code email} ignoring case. {@code wallet_user.email} is unique
     * only exactly, so more than one can exist (EUD-315 decision P16).
     */
    Flux<WalletUser> findAllByEmailIgnoreCase(String email);

    /**
     * Reads the account and locks its row until the end of the transaction, so two registrations
     * with onboarding tickets of the same account are serialized (EUD-315 decision P7).
     */
    Mono<WalletUser> lockById(UUID id);

    Mono<WalletUser> save(WalletUser user);
}
