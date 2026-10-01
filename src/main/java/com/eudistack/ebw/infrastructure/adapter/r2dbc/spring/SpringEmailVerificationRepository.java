package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.EmailVerificationEntity;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringEmailVerificationRepository extends ReactiveCrudRepository<EmailVerificationEntity, UUID> {

    // No expiry filter: OtpService must see an expired row to raise OtpExpiredException
    // instead of treating it as "no code" (#1061173).
    Mono<EmailVerificationEntity> findFirstByUserEmailAndUsedFalseOrderByCreatedAtDesc(String email);

    @Modifying
    @Query("UPDATE email_verification SET used = true WHERE user_email = :email AND used = false")
    Mono<Void> invalidateByEmail(String email);
}
