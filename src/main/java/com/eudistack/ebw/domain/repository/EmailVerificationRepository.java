package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.EmailVerification;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface EmailVerificationRepository {

    Mono<EmailVerification> findLatestUnusedByEmail(String email);

    Mono<EmailVerification> save(EmailVerification verification);

    /** Marks the email's unused codes as used and replaced by a newer one. */
    Mono<Void> invalidateByEmail(String email);

    /** Codes of the email replaced by a newer one since {@code since}, newest first (at most a few). */
    Flux<EmailVerification> findReplacedSince(String email, Instant since);

    /** Atomically marks the code as used if it is unused and has attempts left. Emits {@code true} if it did. */
    Mono<Boolean> markUsedIfUsable(UUID id, int maxAttempts);

    /** Atomically adds a failed attempt. Emits the new number of attempts. */
    Mono<Integer> incrementAttempts(UUID id);
}
