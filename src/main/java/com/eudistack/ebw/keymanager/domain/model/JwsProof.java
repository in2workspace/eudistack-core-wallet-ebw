package com.eudistack.ebw.keymanager.domain.model;

import java.util.Objects;

/**
 * Immutable value object representing a JWS compact serialization produced as a
 * {@code jwt} proof during OID4VCI credential issuance.
 *
 * <p>The compact serialization follows the three-part base64url encoding defined in
 * RFC 7515 §7.2: {@code BASE64URL(JWS Protected Header) || '.' || BASE64URL(JWS Payload)
 * || '.' || BASE64URL(JWS Signature)}.</p>
 *
 * <p>Spec: OID4VCI 1.0 §8.2, Appendix F.1; RFC 7515 §7.2.</p>
 */
public record JwsProof(String compactSerialization, KeyAlgorithm algorithm) {

    public JwsProof {
        Objects.requireNonNull(compactSerialization, "compactSerialization must not be null");
        if (compactSerialization.isBlank()) {
            throw new IllegalArgumentException("compactSerialization must not be blank");
        }
        Objects.requireNonNull(algorithm, "algorithm must not be null");
    }
}