package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletInstance.RevokedBy;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Revokes the Wallet Instances of the current tenant that have bound no session for {@link #INACTIVITY} (EUD-15
 * FR-18, design §2.1), with the same effects as a revocation by the holder and {@code revoked_by = INACTIVITY}.
 * No email. In batches of {@value #BATCH_SIZE}, each in its own transaction with its traces; the conditional
 * update never overwrites a concurrent binding. An instance's last use is set when a session binds to it, so a
 * session bound 89 days ago keeps it active.
 */
@Service
public class RevokeInactiveWalletInstancesWorkflow {

    static final Duration INACTIVITY = Duration.ofDays(90);
    static final int BATCH_SIZE = 500;

    private final WalletInstanceRepository instanceRepository;
    private final WalletInstanceRevoker revoker;
    private final TransactionRunner transactionRunner;

    public RevokeInactiveWalletInstancesWorkflow(WalletInstanceRepository instanceRepository,
                                                 WalletInstanceRevoker revoker, TransactionRunner transactionRunner) {
        this.instanceRepository = instanceRepository;
        this.revoker = revoker;
        this.transactionRunner = transactionRunner;
    }

    /** Requires the tenant in the Reactor context. Emits the number of instances revoked. */
    public Mono<Long> revokeInactive() {
        var cutoff = Instant.now().minus(INACTIVITY);
        return revokeBatches(cutoff, 0L);
    }

    private Mono<Long> revokeBatches(Instant cutoff, long revokedSoFar) {
        return transactionRunner.inTransaction(instanceRepository.revokeInactiveBatch(cutoff, BATCH_SIZE)
                        .concatMap(instance -> afterRevoked(instance).thenReturn(instance))
                        .count())
                .flatMap(revoked -> revoked < BATCH_SIZE
                        ? Mono.just(revokedSoFar + revoked)
                        : revokeBatches(cutoff, revokedSoFar + revoked));
    }

    /**
     * Its sessions end; other service instances see it within the 10-second cache. A session bound to it would
     * have refreshed its last use, so in practice there are none.
     */
    private Mono<Void> afterRevoked(WalletInstance instance) {
        return revoker.afterMarkedRevoked(instance.id(), instance.userId(), RevokedBy.INACTIVITY, null).then();
    }
}
