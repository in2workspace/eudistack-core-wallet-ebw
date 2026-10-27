package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import reactor.core.publisher.Mono;

public interface OnboardingDisavowalRepository {

    Mono<OnboardingDisavowal> insert(OnboardingDisavowal disavowal);

    /**
     * Atomically consumes a usable token (not consumed, not expired), in one conditional
     * {@code UPDATE ... RETURNING}. Emits it only to the caller that consumed it; empty otherwise.
     */
    Mono<OnboardingDisavowal> consume(String tokenHash);

    /** Deletes the consumed or expired tokens. Emits the number of deleted rows. */
    Mono<Long> deleteConsumedOrExpired();
}
