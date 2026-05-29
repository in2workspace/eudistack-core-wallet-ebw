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
 * <p>Per AD-119-3: two distinct event types are used for key generation — {@link KeyAuditEventType#KEY_GENERATED}
 * for new key pairs, and {@link KeyAuditEventType#KEY_FETCHED} for idempotent reuse (EC-01).
 * This preserves full audit fidelity for external reviewers (NIS2, ENS).</p>
 *
 * <p>Per AD-407-3 (US-03): four additional event types cover the signing lifecycle —
 * {@link KeyAuditEventType#KEY_SIGNED} for successful signatures,
 * {@link KeyAuditEventType#SIGN_REJECTED} for opaque rejections (sub-cause in {@code reason}),
 * {@link KeyAuditEventType#SIGN_TIMEOUT} for timeout kill-switch (ES-05),
 * {@link KeyAuditEventType#SIGN_DEPENDENCY_FAILURE} for DB/infra unavailability (ES-04).</p>
 *
 * <p>The optional fields {@code signingType}, {@code purpose}, and {@code consumerOrigin}
 * are only populated for signing events. Generation events leave them {@code null} to
 * preserve backward-compatibility with US-02 audit consumers.</p>
 *
 * <p>Spec: ADR-062 (hash chain audit batches), ADR-069 (audit log platform model),
 * FR-61 (audit Dominio D2), EUDISTACK-407 AC-08.</p>
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
        String correlationId,
        // Optional fields — null for generation events (US-02 backward-compat)
        SigningType signingType,
        SignaturePurpose purpose,
        ConsumerOrigin consumerOrigin,
        String reason
) {

    /**
     * Audit event types for key lifecycle operations.
     */
    public enum KeyAuditEventType {
        /** A new key pair was generated and persisted for the first time. */
        KEY_GENERATED,
        /** An existing key was fetched due to idempotent reuse (EC-01 concurrent request). */
        KEY_FETCHED,
        /** A signing operation completed successfully (US-03 happy path). */
        KEY_SIGNED,
        /**
         * A signing request was rejected. The {@code reason} field (audit-only, not sent to HTTP
         * client) encodes the sub-cause: {@code KEY_NOT_FOUND}, {@code KEY_REVOKED},
         * {@code CROSS_TENANT}, or {@code SIGNING_TYPE_FORMAT_MISMATCH}.
         */
        SIGN_REJECTED,
        /** Signing timed out (kill-switch 2.5 s — ES-05). */
        SIGN_TIMEOUT,
        /** A dependency (DB) was unavailable during signing (ES-04). */
        SIGN_DEPENDENCY_FAILURE
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
        // signingType, purpose, consumerOrigin, reason are intentionally nullable
        // (null for KEY_GENERATED / KEY_FETCHED — US-02 backward-compat)
    }

    /**
     * Factory for US-02 generation events (backward-compat — signing fields are null).
     */
    public static KeyAuditEvent forGeneration(
            KeyAuditEventType type,
            String tenantId,
            String holderId,
            String credentialId,
            CredentialFormat format,
            KeyAlgorithm algorithm,
            String jkt,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                type, tenantId, holderId, credentialId, format, algorithm,
                jkt, timestamp, correlationId,
                null, null, null, null);
    }

    /**
     * Factory for US-03 signing events (all fields populated).
     */
    public static KeyAuditEvent forSigning(
            KeyAuditEventType type,
            String tenantId,
            String holderId,
            String credentialId,
            CredentialFormat format,
            KeyAlgorithm algorithm,
            String jkt,
            Instant timestamp,
            String correlationId,
            SigningType signingType,
            SignaturePurpose purpose,
            ConsumerOrigin consumerOrigin,
            String reason) {
        return new KeyAuditEvent(
                type, tenantId, holderId, credentialId, format, algorithm,
                jkt, timestamp, correlationId,
                signingType, purpose, consumerOrigin, reason);
    }
}
