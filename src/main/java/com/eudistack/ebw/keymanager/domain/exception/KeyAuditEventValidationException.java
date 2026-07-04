package com.eudistack.ebw.keymanager.domain.exception;

/**
 * Thrown when a {@link com.eudistack.ebw.keymanager.domain.model.KeyAuditEvent} is constructed
 * with a missing or inconsistent field for its event type (compact constructor validation).
 *
 * <p>This is a programming-error signal — audit events are always assembled server-side from
 * already-validated data, so this exception indicates a defect in the caller, not user input.</p>
 *
 * <p>Spec: ADR-062 (hash chain audit batches), ADR-069 (audit log platform model),
 * FR-61 (audit Dominio D2).</p>
 */
public class KeyAuditEventValidationException extends RuntimeException {

    public KeyAuditEventValidationException(String reason) {
        super(reason);
    }
}
