package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

public interface WalletCredentialRepository {

    /**
     * Insert a brand-new credential row. Caller MUST guarantee the credential is new
     * (i.e. domain-generated UUID that does not yet exist in the database).
     */
    Mono<WalletCredential> insert(WalletCredential credential);

    /**
     * Update an existing credential row. Caller MUST guarantee the credential was
     * previously loaded from the database (i.e. its id already exists).
     */
    Mono<WalletCredential> update(WalletCredential credential);

    Mono<WalletCredential> findByIdAndUserId(UUID id, UUID userId);

    Flux<WalletCredential> findAllByUserId(UUID userId);

    Flux<WalletCredential> findAllByUserIdAndFilters(UUID userId, CredentialStatus status,
                                                      String credentialConfigId, String issuer);

    /**
     * Attestations obtained with passkey custody whose passkey is no longer in the account ({@code passkey_id}
     * is null) and whose expiration date is before {@code now}. Those without an expiration date, and those of
     * server custody (which never have a passkey to lose), are not returned.
     */
    Flux<WalletCredential> findOrphanedExpired(Instant now);

    /** Emits {@code true} if this call deleted the row, {@code false} if it was already gone. */
    Mono<Boolean> deleteIfExists(UUID id);
}
