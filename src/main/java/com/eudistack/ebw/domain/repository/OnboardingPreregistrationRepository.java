package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface OnboardingPreregistrationRepository {

    Mono<OnboardingPreregistration> insert(OnboardingPreregistration preregistration);

    /**
     * Atomically redeems the ticket: only a pre-registration not redeemed and not expired, in one
     * conditional {@code UPDATE ... RETURNING}. Emits it only to the caller that redeemed it;
     * empty for an unknown, used or expired ticket.
     */
    Mono<OnboardingPreregistration> redeem(String tokenHash);

    /** Sets the WebAuthn user handle of the future account (EUD-315 decision P2, provisional). */
    Mono<Void> assignUserHandle(UUID id, byte[] webauthnUserHandle);

    /**
     * Keeps the pre-registration at least until {@code until}: the registration ticket of its
     * redemption needs it (EUD-315 decision P8, provisional). Never shortens it.
     */
    Mono<Void> keepUntil(UUID id, Instant until);

    Mono<OnboardingPreregistration> findById(UUID id);

    /** Physically deletes it (with its email). Emits {@code true} if the row existed. */
    Mono<Boolean> deleteById(UUID id);

    /** Physically deletes the expired pre-registrations, redeemed or not, and emits each one for the audit trail. */
    Flux<ExpiredPreregistration> deleteExpired();
}
