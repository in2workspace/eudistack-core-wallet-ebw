package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface RegistrationTicketRepository {

    Mono<RegistrationTicket> insert(RegistrationTicket ticket);

    /** Returns the ticket if it was not consumed and has not expired; empty otherwise. */
    Mono<RegistrationTicket> findUsableByTokenHash(String tokenHash);

    /** Atomically consumes a usable ticket. Emits {@code true} only for the caller that consumed it. */
    Mono<Boolean> consume(UUID id);

    Mono<Long> deleteCreatedBefore(Instant cutoff);
}
