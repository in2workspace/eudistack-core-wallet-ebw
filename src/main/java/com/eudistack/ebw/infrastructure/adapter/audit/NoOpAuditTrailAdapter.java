package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Stand-in for the audit trail until the audit outbox starter is available: it records nothing, so
 * wiring the use cases to the port changes no behaviour. The adapter that stages entries in the outbox
 * replaces it.
 */
@Component
public class NoOpAuditTrailAdapter implements AuditTrailPort {

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        return Mono.empty();
    }
}
