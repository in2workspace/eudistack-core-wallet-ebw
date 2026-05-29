package com.eudistack.ebw.keymanager.domain.model;

import jakarta.annotation.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * Command carrying all inputs required to generate a holder key and produce a
 * {@code jwt} proof during OID4VCI credential issuance.
 *
 * <p>{@code cNonce} is nullable per OID4VCI 1.0 §7.2 (the Nonce Endpoint is optional;
 * if the issuer does not publish one, the {@code c_nonce} claim is omitted from the proof).</p>
 *
 * <p>Spec: OID4VCI 1.0 §7 (Token Request / Credential Request flow), §8.2 (jwt proof type),
 * ADR-021 (key-per-credential), ADR-024 (algorithm negotiation).</p>
 */
public record GenerateHolderKeyCommand(
        String tenantId,
        String holderId,
        String credentialId,
        CredentialFormat format,
        List<String> supportedAlgs,
        String issuerIdentifier,
        @Nullable String cNonce
) {

    public GenerateHolderKeyCommand {
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
        Objects.requireNonNull(supportedAlgs, "supportedAlgs must not be null");
        if (supportedAlgs.isEmpty()) {
            throw new IllegalArgumentException("supportedAlgs must not be empty");
        }
        Objects.requireNonNull(issuerIdentifier, "issuerIdentifier must not be null");
        if (issuerIdentifier.isBlank()) {
            throw new IllegalArgumentException("issuerIdentifier must not be blank");
        }
        // cNonce is intentionally nullable — see OID4VCI 1.0 §7.2 (EC-05)
    }
}