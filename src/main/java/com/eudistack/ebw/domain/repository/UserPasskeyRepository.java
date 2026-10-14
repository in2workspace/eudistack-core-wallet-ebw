package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyAssertion;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface UserPasskeyRepository {

    Flux<UserPasskey> findByUserId(UUID userId);

    Mono<UserPasskey> findByIdAndUserId(UUID id, UUID userId);

    /** Credential ids are unique in the tenant. */
    Mono<UserPasskey> findByCredentialId(String credentialId);

    Mono<UserPasskey> insert(UserPasskey passkey);

    Mono<UserPasskey> updateDisplayName(UserPasskey passkey);

    /**
     * Stores the authenticator state after a verified authentication and sets the last use.
     * When the new signature counter is greater than 0 the update only applies if the stored
     * counter is lower ({@code WHERE sign_count < :signCount}), so two concurrent sign-ins
     * with the same counter cannot both succeed. Emits {@code true} if the row was updated.
     */
    Mono<Boolean> recordAuthentication(UUID id, VerifiedPasskeyAssertion assertion);

    Mono<Void> deleteById(UUID id);

    Mono<Long> countByUserId(UUID userId);

    Mono<Void> touchLastUsed(UUID id);
}
