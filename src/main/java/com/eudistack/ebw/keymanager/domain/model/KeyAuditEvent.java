package com.eudistack.ebw.keymanager.domain.model;

import jakarta.annotation.Nullable;

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
 * <p>The optional fields {@code signingType}, {@code purpose}, {@code consumerOrigin},
 * and {@code keyId} are only populated for signing events. Generation events leave them
 * {@code null} to preserve backward-compatibility with US-02 audit consumers.</p>
 *
 * <p>{@code keyId} carries the surrogate UUID of the {@link HolderKey} that was used for the
 * signing operation. It is absent ({@code null}) for generation events (US-02) because no key
 * is being used as an instrument — it is being created. For signing events (US-03), the field
 * allows an auditor to correlate the signing event with the key lifecycle event without
 * exposing key material.</p>
 *
 * <p>Spec: ADR-062 (hash chain audit batches), ADR-069 (audit log platform model),
 * FR-61 (audit Dominio D2), EUDISTACK-407 AC-08.</p>
 */
public record KeyAuditEvent(
        KeyAuditEventType type,
        String tenantId,
        String holderId,
        // Null for CONSTRAINT_ACCEPTED events (no key or credential yet — US-06)
        @Nullable String credentialId,
        @Nullable CredentialFormat format,
        @Nullable KeyAlgorithm algorithm,
        @Nullable String jkt,
        Instant timestamp,
        String correlationId,
        // Optional fields — null for generation events (US-02 backward-compat)
        @Nullable SigningType signingType,
        @Nullable SignaturePurpose purpose,
        @Nullable ConsumerOrigin consumerOrigin,
        @Nullable String reason,
        @Nullable String keyId
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
        SIGN_DEPENDENCY_FAILURE,
        /** Holder accepted the multi-device constraint before hybrid onboarding (US-06, EUDISTACK-538). */
        CONSTRAINT_ACCEPTED,
        /** Holder key wrapped and committed after client-side generation (US-08, EUDISTACK-540). */
        WRAP_COMPLETED,
        /** Holder key unwrapped and signing completed in hybrid two-step flow (US-04/US-08). */
        UNWRAP_SIGN_COMPLETED,
        /** Holder key unwrap failed during hybrid signing (US-04/US-08). */
        UNWRAP_FAILED,
        /** Hybrid onboarding blocked — holder device does not support Passkey PRF (US-08, EUDISTACK-540). */
        ONBOARDING_BLOCKED_PRF_UNSUPPORTED
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
        // Types where no key context exists yet (consent / device-blocked events)
        boolean noKeyContext = type == KeyAuditEventType.CONSTRAINT_ACCEPTED
                || type == KeyAuditEventType.ONBOARDING_BLOCKED_PRF_UNSUPPORTED;
        // Types where credentialId is present but format/algorithm/jkt are not available server-side
        // (key was generated and wrapped client-side — US-08)
        boolean wrapContext = type == KeyAuditEventType.WRAP_COMPLETED;

        if (!noKeyContext) {
            Objects.requireNonNull(credentialId, "credentialId must not be null");
            if (credentialId.isBlank()) {
                throw new IllegalArgumentException("credentialId must not be blank");
            }
        }
        if (!noKeyContext && !wrapContext) {
            Objects.requireNonNull(format, "format must not be null");
            Objects.requireNonNull(algorithm, "algorithm must not be null");
            Objects.requireNonNull(jkt, "jkt must not be null");
            if (jkt.isBlank()) {
                throw new IllegalArgumentException("jkt must not be blank");
            }
        }
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        if (correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
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
                null, null, null, null, null);
    }

    /**
     * Factory for US-06 consent events — no key material exists yet.
     * credentialId, format, algorithm, and jkt are null by design.
     */
    public static KeyAuditEvent forConsent(
            String tenantId,
            String holderId,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                KeyAuditEventType.CONSTRAINT_ACCEPTED,
                tenantId, holderId,
                null, null, null, null,
                timestamp, correlationId,
                null, null, null, null, null);
    }

    /**
     * Factory for US-08 wrap events — key was generated and wrapped client-side.
     * format, algorithm, and jkt are null because the server never holds the plaintext key.
     */
    public static KeyAuditEvent forWrap(
            String tenantId,
            String holderId,
            String credentialId,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                KeyAuditEventType.WRAP_COMPLETED,
                tenantId, holderId,
                credentialId, null, null, null,
                timestamp, correlationId,
                null, null, null, null, null);
    }

    /**
     * Factory for US-08 PRF-unsupported events — onboarding blocked at device level, no key material.
     */
    public static KeyAuditEvent forPrfUnsupported(
            String tenantId,
            String holderId,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                KeyAuditEventType.ONBOARDING_BLOCKED_PRF_UNSUPPORTED,
                tenantId, holderId,
                null, null, null, null,
                timestamp, correlationId,
                null, null, null, null, null);
    }

    /**
     * Factory for US-03 signing events (all fields populated).
     *
     * @param keyId the surrogate UUID of the {@link HolderKey} used for signing; may be null
     *              for SIGN_DEPENDENCY_FAILURE and SIGN_TIMEOUT events where the key may not
     *              have been resolved yet
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
            String reason,
            @Nullable String keyId) {
        return new KeyAuditEvent(
                type, tenantId, holderId, credentialId, format, algorithm,
                jkt, timestamp, correlationId,
                signingType, purpose, consumerOrigin, reason, keyId);
    }
}
