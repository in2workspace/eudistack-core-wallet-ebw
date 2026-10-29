package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface WebAuthnCeremonyRepository {

    Mono<WebAuthnCeremony> insert(WebAuthnCeremony ceremony);

    /**
     * Atomically marks the ceremony as consumed and returns it, only if it exists, has the
     * given type, was not consumed and has not expired. Of two concurrent calls, at most one
     * gets the ceremony; the other completes empty.
     */
    Mono<WebAuthnCeremony> consume(UUID id, CeremonyType type);

    Mono<Long> deleteCreatedBefore(Instant cutoff);
}
