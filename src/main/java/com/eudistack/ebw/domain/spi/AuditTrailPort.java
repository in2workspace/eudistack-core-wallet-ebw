package com.eudistack.ebw.domain.spi;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import reactor.core.publisher.Mono;

/**
 * Output port to the audit trail (EUD-244): the use case states what happened and the adapter hands it
 * to the audit outbox. The domain depends only on this interface, never on the outbox starter.
 *
 * <p>The tenant, actor and correlation id are read from the audit context of the operation, not passed here.
 */
public interface AuditTrailPort {

    /**
     * Stages the entry in a short transaction of its own, for facts that have no business write to join,
     * such as a call to a third party.
     */
    Mono<Void> stageInNewTransaction(AuditEntry entry);

    /**
     * Stages the entry in a transaction of its own and never fails the caller: for a fact that already
     * happened outside any business write (a mail sent), where a broken audit channel must not undo or
     * hide the operation. The adapter reports the failure itself.
     */
    default Mono<Void> stageBestEffort(AuditEntry entry) {
        return stageInNewTransaction(entry).onErrorResume(_ -> Mono.empty());
    }
}
