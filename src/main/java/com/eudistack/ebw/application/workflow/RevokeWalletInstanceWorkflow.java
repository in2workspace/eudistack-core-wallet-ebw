package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletInstance.RevokedBy;
import com.eudistack.ebw.domain.model.exception.WalletInstanceNotFoundException;
import com.eudistack.ebw.domain.repository.WalletInstanceRepository;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * The holder revokes a Wallet Instance of their account, also the current one (EUD-15 FR-13 to FR-16): it is
 * marked revoked and every session bound to it ends, in one transaction. An already revoked instance is
 * answered as revoked again, with no effect; another account's is not found. Emits the sessions that ended, so
 * the caller forgets their cached state on this service instance at once (the others within 10 seconds).
 */
@Service
public class RevokeWalletInstanceWorkflow {

    private final WalletInstanceRepository instanceRepository;
    private final WalletInstanceRevoker revoker;
    private final TransactionRunner transactionRunner;

    public RevokeWalletInstanceWorkflow(WalletInstanceRepository instanceRepository, WalletInstanceRevoker revoker,
                                        TransactionRunner transactionRunner) {
        this.instanceRepository = instanceRepository;
        this.revoker = revoker;
        this.transactionRunner = transactionRunner;
    }

    public Mono<List<UUID>> revoke(WalletSession session, UUID instanceId) {
        return transactionRunner.inTransaction(instanceRepository.findByIdAndUserId(instanceId, session.userId())
                .switchIfEmpty(Mono.error(new WalletInstanceNotFoundException()))
                .flatMap(instance -> instance.isActive()
                        ? revoker.revoke(instance, RevokedBy.HOLDER, session.userId(),
                                Objects.equals(instance.id(), session.walletInstanceId()))
                        : Mono.just(List.<UUID>of())));
    }
}
