package com.eudistack.ebw.infrastructure.adapter.audit;

import com.eudistack.ebw.domain.model.audit.AuditEntry;
import com.eudistack.ebw.domain.model.audit.AuditEventType;
import com.eudistack.ebw.domain.model.audit.ExternalSystemTarget;
import com.eudistack.ebw.domain.spi.AuditTrailPort;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Records an {@code ExternalSystemAccess} event around a call to a third party (the mail provider).
 *
 * <p>The call has no business write to join, so the event goes in a transaction of its own, best effort:
 * the third party has already been called, and a broken audit channel must neither turn a delivered
 * email into a failed one nor hide the call's own error.
 */
@Component
public class ExternalSystemAccessRecorder {

    private final AuditTrailPort auditTrail;

    public ExternalSystemAccessRecorder(AuditTrailPort auditTrail) {
        this.auditTrail = auditTrail;
    }

    public <T> Mono<T> recordAccess(ExternalSystemTarget target, String operation, Mono<T> call) {
        return Mono.defer(() -> {
            long startedAt = System.nanoTime();
            return call
                    .flatMap(value -> stage(target, operation, startedAt, null).thenReturn(value))
                    .switchIfEmpty(Mono.defer(() -> stage(target, operation, startedAt, null).then(Mono.<T>empty())))
                    .onErrorResume(error -> stage(target, operation, startedAt, error).then(Mono.<T>error(error)));
        });
    }

    private Mono<Void> stage(ExternalSystemTarget target, String operation, long startedAt, Throwable error) {
        long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
        Map<String, Object> details = Map.of(
                "system_type", target.systemType(),
                "system", target.system(),
                "operation", operation,
                "authentication_method", target.authenticationMethod(),
                "duration_ms", durationMs);
        String resource = "external-system:" + target.system();
        AuditEntry entry = error == null
                ? AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, resource, details)
                : AuditEntry.forReason(AuditEventType.EXTERNAL_SYSTEM_ACCESS, resource,
                        ExternalFailureClassifier.reasonOf(error), details);
        return auditTrail.stageBestEffort(entry);
    }
}
