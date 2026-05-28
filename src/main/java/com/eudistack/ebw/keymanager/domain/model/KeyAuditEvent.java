package com.eudistack.ebw.keymanager.domain.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Domain event emitted to the audit Dominio D2 for every security-relevant key operation.
 *
 * <p>This record intentionally contains NO key material (no private key bytes, no raw JWK
 * with private components). The {@code jkt} field is the JWK Thumbprint per RFC 7638,
 * which identifies the key without exposing it.</p>
 *
 * <p>Per AD-119-3: two distinct event types are used — {@link KeyAuditEventType#KEY_GENERATED}
 * for new key pairs, and {@link KeyAuditEventType#KEY_FETCHED} for idempotent reuse (EC-01).
 * This preserves full audit fidelity for external reviewers (NIS2, ENS).</p>
 *
 * <p>Spec: ADR-062 (hash chain audit batches), ADR-069 (audit log platform model),
 * FR-61 (audit Dominio D2).</p>
 */
public record KeyAuditEvent(
        KeyAuditEventType type,
        String tenantId,
        String holderId,
        String credentialId,
        CredentialFormat format,
        KeyAlgorithm algorithm,
        String jkt,
        Instant timestamp,
        String correlationId
) {

    /**
     * Audit event types for key lifecycle operations.
     */
    public enum KeyAuditEventType {
        /** A new key pair was generated and persisted for the first time. */
        KEY_GENERATED,
        /** An existing key was fetched due to idempotent reuse (EC-01 concurrent request). */
        KEY_FETCHED
    }

    public KeyAuditEvent {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        Objects.requireNonNull(holderId, "holderId must not be null");
        if (holderId.isBlank()) {
            throw new IllegalArgumentException("holderId must not be blank");
        }
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        if (credentialId.isBlank()) {
            throw new IllegalArgumentException("credentialId must not be blank");
        }
        Objects.requireNonNull(format, "format must not be null");
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(jkt, "jkt must not be null");
        if (jkt.isBlank()) {
            throw new IllegalArgumentException("jkt must not be blank");
        }
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        if (correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
    }
}