package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.auditoria.application.ReactiveAuditPublisher;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditFact;
import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import reactor.core.publisher.Mono;

import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Hands the entries of the use cases to the audit outbox starter. It opens a transaction of its own, since
 * the starter never does (EC-09).
 */
@Slf4j
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class StarterAuditTrailAdapter implements AuditTrailPort {

    private final ReactiveAuditPublisher publisher;
    private final TransactionalOperator ownTransaction;

    public StarterAuditTrailAdapter(ReactiveAuditPublisher publisher, ReactiveTransactionManager transactionManager) {
        this.publisher = publisher;
        this.ownTransaction = TransactionalOperator.create(
                transactionManager, new DefaultTransactionDefinition(PROPAGATION_REQUIRES_NEW));
    }

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        return Mono.defer(() -> ownTransaction.transactional(publisher.stage(draftOf(entry))))
                .doOnError(error -> reportFailure(entry, error));
    }

    private static AuditDraft draftOf(AuditEntry entry) {
        AuditFact fact = AuditFact.builder(entry.type().catalogName())
                .action(entry.type().action())
                .resource(entry.resource())
                .details(entry.details())
                .source(entry.source())
                .build();
        return switch (entry.result()) {
            case SUCCESS -> AuditDraft.success(fact);
            case DENIED -> AuditDraft.denied(fact, entry.reason());
            case FAILURE -> AuditDraft.failure(fact, entry.reason());
        };
    }

    /** Only the type and the kind of error are logged: the entry carries personal data. */
    private static void reportFailure(AuditEntry entry, Throwable error) {
        log.warn("action=stageAuditEvent status=failed eventType={} error={}",
                entry.type().catalogName(), error.getClass().getSimpleName());
    }
}
