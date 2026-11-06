package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Registration tickets: opaque, 32 random bytes in base64url, single account, valid 5 minutes,
 * single use. Only their SHA-256 is stored.
 */
public class RegistrationTicketService {

    private static final int TICKET_BYTES = 32;

    private final RegistrationTicketRepository ticketRepository;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;

    public RegistrationTicketService(RegistrationTicketRepository ticketRepository, HashProvider hashProvider,
                                     SecureRandomGenerator randomGenerator) {
        this.ticketRepository = ticketRepository;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
    }

    /** Issues a ticket for the account. Emits the raw ticket, which is never stored. */
    public Mono<String> issue(UUID userId) {
        var raw = Base64.getUrlEncoder().withoutPadding().encodeToString(randomGenerator.generateBytes(TICKET_BYTES));
        return ticketRepository.insert(RegistrationTicket.issue(userId, hashProvider.sha256(raw)))
                .thenReturn(raw);
    }

    /** A raw registration ticket, never stored, and when it expires. */
    public record IssuedTicket(String raw, Instant expiresAt) {
        @Override
        public String toString() {
            return "IssuedTicket[raw=[redacted], expiresAt=" + expiresAt + "]";
        }
    }

    /**
     * Issues the ticket of a redeemed onboarding ticket, bound to its pre-registration and, if the
     * email has one, to the account. Emits the raw ticket, which is never stored.
     */
    public Mono<IssuedTicket> issueForPreregistration(UUID userId, UUID preregistrationId) {
        var raw = Base64.getUrlEncoder().withoutPadding().encodeToString(randomGenerator.generateBytes(TICKET_BYTES));
        var ticket = RegistrationTicket.issueForPreregistration(userId, preregistrationId, hashProvider.sha256(raw));
        return ticketRepository.insert(ticket).thenReturn(new IssuedTicket(raw, ticket.expiresAt()));
    }

    /** Resolves a usable (not consumed, not expired) ticket, or fails with {@link InvalidTicketException}. */
    public Mono<RegistrationTicket> resolve(String rawTicket) {
        if (rawTicket == null || rawTicket.isBlank()) {
            return Mono.error(new InvalidTicketException());
        }
        return ticketRepository.findUsableByTokenHash(hashProvider.sha256(rawTicket))
                .switchIfEmpty(Mono.error(new InvalidTicketException()));
    }

    /** Consumes the ticket atomically; fails with {@link InvalidTicketException} if it is no longer usable. */
    public Mono<Void> consume(RegistrationTicket ticket) {
        return ticketRepository.consume(ticket.id())
                .flatMap(consumed -> Boolean.TRUE.equals(consumed)
                        ? Mono.<Void>empty()
                        : Mono.error(new InvalidTicketException()));
    }
}
