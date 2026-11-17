package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The audit trail while the publisher is off: it records nothing, so the use cases behave the same with
 * auditing on or off.
 */
@Component
@ConditionalOnBooleanProperty(name = "auditoria.publisher.enabled", havingValue = false, matchIfMissing = true)
public class NoOpAuditTrailAdapter implements AuditTrailPort {

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        return Mono.empty();
    }
}
