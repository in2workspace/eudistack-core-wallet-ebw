package com.eudistack.ebw.keymanager.domain.model;

/**
 * JWS algorithms supported by the Key Manager for holder key generation.
 *
 * <p>Each constant carries the JWS algorithm name (used in JOSE headers) and the
 * corresponding curve name (used in JWK construction and JCA key generation).</p>
 *
 * <p>Preference order per ADR-024: EdDSA &gt; ES384 &gt; ES256.</p>
 *
 * <p>Spec: RFC 7518 §3, OID4VCI 1.0 §8.2, ADR-024.</p>
 */
public enum KeyAlgorithm {

    ES256("ES256", "P-256"),
    ES384("ES384", "P-384"),
    EdDSA("EdDSA", "Ed25519");

    private final String jwsAlgorithmName;
    private final String curveName;

    KeyAlgorithm(String jwsAlgorithmName, String curveName) {
        this.jwsAlgorithmName = jwsAlgorithmName;
        this.curveName = curveName;
    }

    public String getJwsAlgorithmName() {
        return jwsAlgorithmName;
    }

    public String getCurveName() {
        return curveName;
    }
}