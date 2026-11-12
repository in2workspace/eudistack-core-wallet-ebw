package com.eudistack.ebw.infrastructure.adapter.r2dbc.spring;

import com.eudistack.ebw.infrastructure.adapter.r2dbc.entity.WalletUserEntity;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface SpringWalletUserRepository extends ReactiveCrudRepository<WalletUserEntity, UUID> {

    Mono<WalletUserEntity> findByEmail(String email);

    @Query("SELECT * FROM wallet_user WHERE lower(email) = lower(:email)")
    Flux<WalletUserEntity> findAllByEmailIgnoreCase(String email);

    @Query("SELECT * FROM wallet_user WHERE id = :id FOR UPDATE")
    Mono<WalletUserEntity> lockById(UUID id);

    /** Transaction-scoped advisory lock on the email ignoring case; the row only signals the lock was taken. */
    @Query("SELECT 1 FROM pg_advisory_xact_lock(hashtext(lower(:email)))")
    Mono<Integer> lockEmailIgnoreCase(String email);
}
