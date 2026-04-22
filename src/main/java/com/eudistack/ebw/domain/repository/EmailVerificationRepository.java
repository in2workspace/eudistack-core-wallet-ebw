package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.EmailVerification;
import reactor.core.publisher.Mono;

public interface EmailVerificationRepository {

    Mono<EmailVerification> findActiveByEmail(String email);

    Mono<EmailVerification> save(EmailVerification verification);

    Mono<Void> invalidateByEmail(String email);
}
