package com.eudistack.ebw.keymanager.domain.model;

/**
 * Signing type requested by the consumer when invoking the server-side signing endpoint.
 *
 * <p>Each type maps to a specific JWS {@code typ} header value and is compatible with
 * exactly one {@link CredentialFormat}. The compatibility rule enforces that the holder
 * key stored for a credential in a given format is only used to produce the signing
 * artefact that is semantically coherent for that format.</p>
 *
 * <p>Mapping (per ADR-024 / RFC 9901 / VC-JOSE-COSE):
 * <ul>
 *   <li>{@code KB_JWT} ↔ {@link CredentialFormat#SD_JWT_VC} — key-binding JWT (RFC 9901 §4.1.2)</li>
 *   <li>{@code VP_ENVELOPE} ↔ {@link CredentialFormat#VC_JWT} — VP JWS envelope
 *       (VC-JOSE-COSE §3.2 + OID4VP Appendix B.1)</li>
 * </ul>
 *
 * <p>Spec: EUDISTACK-407, RFC 9901 §4.1, OID4VP 1.0 §B.1, ADR-024.</p>
 */
public enum SigningType {

    /**
     * Key-binding JWT per RFC 9901 §4.1.2.
     * JWS {@code typ} header value: {@code kb+jwt}.
     * Compatible with {@link CredentialFormat#SD_JWT_VC} keys only.
     */
    KB_JWT,

    /**
     * VP JWS envelope per VC-JOSE-COSE §3.2 + OID4VP Appendix B.1.
     * JWS {@code typ} header value: {@code vp+jwt}.
     * Compatible with {@link CredentialFormat#VC_JWT} keys only.
     */
    VP_ENVELOPE;

    /**
     * Returns true if this signing type is semantically compatible with the given credential format.
     *
     * <p>A consumer MUST verify this before calling the signing use case. The use case also
     * validates this independently ({@code EC-02}).</p>
     *
     * @param format the format of the stored holder key
     * @return true if the pairing is valid
     */
    public boolean isCompatibleWith(CredentialFormat format) {
        return switch (this) {
            case KB_JWT -> format == CredentialFormat.SD_JWT_VC;
            case VP_ENVELOPE -> format == CredentialFormat.VC_JWT;
        };
    }
}
