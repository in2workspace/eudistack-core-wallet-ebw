package com.eudistack.ebw.domain.repository;

import com.eudistack.ebw.domain.model.WalletInstance;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/** Wallet Instances of the tenant (EUD-15) and their binding to the sessions. */
public interface WalletInstanceRepository {

    Mono<WalletInstance> insert(WalletInstance instance);

    /** The instance with that id, only if it belongs to the account. */
    Mono<WalletInstance> findByIdAndUserId(UUID id, UUID userId);

    /** Active instances of the account. */
    Flux<WalletInstance> findActiveByUserId(UUID userId);

    /** Every instance the account has ever registered, active or revoked. */
    Mono<Long> countByUserId(UUID userId);

    /**
     * Sets the last use of an active instance of the account. Conditioned on {@code status = 'ACTIVE'} in the
     * same statement, so a concurrent revocation wins: emits the instance only if it was still active.
     */
    Mono<WalletInstance> touchIfActive(UUID id, UUID userId);

    /** Renames an active instance of the account; empty if there is none. */
    Mono<WalletInstance> renameIfActive(UUID id, UUID userId, String displayName);

    /**
     * Marks an active instance revoked. Emits {@code true} only for the call that revoked it, so a concurrent
     * revocation is traced once.
     */
    Mono<Boolean> revokeIfActive(UUID id, WalletInstance.RevokedBy revokedBy);

    /** Revokes the active instances registered with that passkey ("it was not me"). Emits their ids. */
    Flux<UUID> revokeActiveByRegisteredPasskey(UUID passkeyId, WalletInstance.RevokedBy revokedBy);

    /**
     * Revokes up to {@code limit} active instances not used since {@code cutoff} ({@code coalesce(last_used_at,
     * created_at)}), conditioned on {@code status = 'ACTIVE'} so a concurrent binding is never overwritten.
     * Emits the revoked instances.
     */
    Flux<WalletInstance> revokeInactiveBatch(Instant cutoff, int limit);
}
