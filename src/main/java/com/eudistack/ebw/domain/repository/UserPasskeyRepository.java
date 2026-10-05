package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.UserPasskey;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface UserPasskeyRepository {

    Flux<UserPasskey> findByUserId(UUID userId);

    Mono<UserPasskey> findByIdAndUserId(UUID id, UUID userId);

    Mono<UserPasskey> findByUserIdAndCredentialId(UUID userId, String credentialId);

    Mono<UserPasskey> save(UserPasskey passkey);

    Mono<Void> deleteById(UUID id);

    Mono<Long> countByUserId(UUID userId);

    /** Sets {@code last_used_at} to now: the device behind this passkey just used its session. */
    Mono<Void> touchLastUsed(UUID id);
}
