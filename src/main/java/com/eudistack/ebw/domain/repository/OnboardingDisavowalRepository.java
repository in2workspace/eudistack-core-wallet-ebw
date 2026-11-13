package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface OnboardingDisavowalRepository {

    Mono<OnboardingDisavowal> insert(OnboardingDisavowal disavowal);

    /**
     * Atomically consumes a usable token (not consumed, not expired), in one conditional
     * {@code UPDATE ... RETURNING}. Emits it only to the caller that consumed it; empty otherwise.
     */
    Mono<OnboardingDisavowal> consume(String tokenHash);

    /**
     * Gives a token to the row of the passkey that has none yet, in one conditional
     * {@code UPDATE ... RETURNING}: the new-account email goes out once (EUD-315 decision P6).
     * Empty when the passkey has no row or it already has a token.
     */
    Mono<OnboardingDisavowal> assignToken(UUID passkeyId, String tokenHash, Instant expiresAt);

    /** Deletes the consumed or expired tokens. Emits the number of deleted rows. */
    Mono<Long> deleteConsumedOrExpired();
}
