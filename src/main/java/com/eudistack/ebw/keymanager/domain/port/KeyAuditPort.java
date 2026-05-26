package com.eudistack.ebw.keymanager.domain.port;

import com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent;
import reactor.core.publisher.Mono;

/**
 * Port for emitting key lifecycle audit events to the audit subsystem (Dominio D2).
 *
 * <p>Implementations are expected to be fire-and-forget with best-effort delivery;
 * callers should not block on audit emission for latency-sensitive operations.
 * Retention and signing requirements are handled by the adapter implementation.</p>
 *
 * <p>Spec: ADR-062 (KMS-signed audit batches), ADR-069 (audit log platform model),
 * FR-61 (audit Dominio D2), EUDISTACK-119 AD-119-3.</p>
 */
public interface KeyAuditPort {

    Mono<Void> emit(KeyAuditEvent event);
}