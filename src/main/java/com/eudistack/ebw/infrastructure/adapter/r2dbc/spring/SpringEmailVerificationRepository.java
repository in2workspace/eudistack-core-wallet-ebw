package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.EmailVerificationEntity;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringEmailVerificationRepository extends ReactiveCrudRepository<EmailVerificationEntity, UUID> {

    @Query("SELECT * FROM email_verification WHERE user_email = $1 AND used = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1")
    Mono<EmailVerificationEntity> findActiveByEmail(String email);

    @Modifying
    @Query("UPDATE email_verification SET used = true WHERE user_email = $1 AND used = false")
    Mono<Void> invalidateByEmail(String email);
}
