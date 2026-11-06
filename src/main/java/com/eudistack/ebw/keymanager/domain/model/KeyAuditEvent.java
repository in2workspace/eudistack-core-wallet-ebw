package com.eudistack.ebw.keymanager.domain.model;

import com.eudistack.ebw.domain.model.CustodyMode;
import com.eudistack.ebw.keymanager.domain.exception.KeyAuditEventValidationException;
import jakarta.annotation.Nullable;

import java.time.Instant;

/**
 * Audit event of an operation on a holder key (EUD-11 FR-04). It carries the custody mode and never
 * key material: no private key, no PRF salt, no PRF result.
 */
public record KeyAuditEvent(
        KeyAuditEventType type,
        String tenantId,
        String holderId,
        // Present in every event
        String credentialId,
        // Key context of a server custody signing or generation; absent in key and salt lifecycle events
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
        @Nullable String keyId,
        CustodyMode custodyMode
) {

    public enum KeyAuditEventType {
        KEY_GENERATED,
        KEY_FETCHED,
        KEY_SIGNED,
        SIGN_REJECTED,
        SIGN_TIMEOUT,
        SIGN_DEPENDENCY_FAILURE,
        KEY_DELETED,
        SALT_CREATED,
        SALT_DELIVERED,
        SALT_DELIVERY_DENIED,
        SALT_DELETED;

        /** Events about the life of the key material, not about a signature: they carry no key context. */
        boolean isLifecycle() {
            return this == KEY_DELETED || this == SALT_CREATED || this == SALT_DELIVERED
                    || this == SALT_DELIVERY_DENIED || this == SALT_DELETED;
        }
    }

    public KeyAuditEvent {
        if (type == null)      throw new KeyAuditEventValidationException("type must not be null");
        if (tenantId == null)  throw new KeyAuditEventValidationException("tenantId must not be null");
        if (tenantId.isBlank()) throw new KeyAuditEventValidationException("tenantId must not be blank");
        if (holderId == null)  throw new KeyAuditEventValidationException("holderId must not be null");
        if (holderId.isBlank()) throw new KeyAuditEventValidationException("holderId must not be blank");
        if (credentialId == null) throw new KeyAuditEventValidationException("credentialId must not be null");
        if (credentialId.isBlank()) throw new KeyAuditEventValidationException("credentialId must not be blank");
        if (custodyMode == null) throw new KeyAuditEventValidationException("custodyMode must not be null");

        if (!type.isLifecycle()) {
            if (format == null)    throw new KeyAuditEventValidationException("format must not be null");
            if (algorithm == null) throw new KeyAuditEventValidationException("algorithm must not be null");
            if (jkt == null)    throw new KeyAuditEventValidationException("jkt must not be null");
            if (jkt.isBlank())  throw new KeyAuditEventValidationException("jkt must not be blank");
        }
        if (timestamp == null)     throw new KeyAuditEventValidationException("timestamp must not be null");
        if (correlationId == null) throw new KeyAuditEventValidationException("correlationId must not be null");
        if (correlationId.isBlank()) throw new KeyAuditEventValidationException("correlationId must not be blank");
    }

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
                null, null, null, null, null, CustodyMode.SERVER);
    }

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
                signingType, purpose, consumerOrigin, reason, keyId, CustodyMode.SERVER);
    }

    /** Server custody: the holder key of an attestation was deleted with it. */
    public static KeyAuditEvent forKeyDeleted(
            String tenantId,
            String holderId,
            String credentialId,
            String keyId,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                KeyAuditEventType.KEY_DELETED, tenantId, holderId, credentialId,
                null, null, null, timestamp, correlationId,
                null, null, null, null, keyId, CustodyMode.SERVER);
    }

    /**
     * Passkey custody: an operation on the salt of an attestation.
     *
     * @param type   one of the {@code SALT_*} types
     * @param reason why the salt was not delivered; only for {@code SALT_DELIVERY_DENIED}
     */
    public static KeyAuditEvent forSalt(
            KeyAuditEventType type,
            String tenantId,
            String holderId,
            String credentialId,
            @Nullable String reason,
            Instant timestamp,
            String correlationId) {
        return new KeyAuditEvent(
                type, tenantId, holderId, credentialId,
                null, null, null, timestamp, correlationId,
                null, null, null, reason, null, CustodyMode.PASSKEY);
    }
}
