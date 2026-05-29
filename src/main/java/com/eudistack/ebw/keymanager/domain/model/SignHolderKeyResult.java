package com.eudistack.ebw.keymanager.domain.model;

import java.util.Objects;

/**
 * Result produced by the {@code SignHolderKey} use case.
 *
 * <p>Contains the compact JWS serialization, the algorithm used, and the JWK Thumbprint
 * of the holder key. All fields are public information — the JWS contains only the
 * signature and the signed payload; no private key material is ever included.</p>
 *
 * <p>Spec: EUDISTACK-407, FR-20, RFC 7515 (JWS), RFC 7638 (JWK Thumbprint).</p>
 *
 * @param jwsCompact the JWS in compact serialization (header.payload.signature)
 * @param algorithm  the algorithm used to produce the signature
 * @param jkt        JWK Thumbprint (RFC 7638) identifying the holder public key
 */
public record SignHolderKeyResult(
        String jwsCompact,
        KeyAlgorithm algorithm,
        String jkt
) {

    public SignHolderKeyResult {
        Objects.requireNonNull(jwsCompact, "jwsCompact must not be null");
        if (jwsCompact.isBlank()) {
            throw new IllegalArgumentException("jwsCompact must not be blank");
        }
        Objects.requireNonNull(algorithm, "algorithm must not be null");
        Objects.requireNonNull(jkt, "jkt must not be null");
        if (jkt.isBlank()) {
            throw new IllegalArgumentException("jkt must not be blank");
        }
    }
}
