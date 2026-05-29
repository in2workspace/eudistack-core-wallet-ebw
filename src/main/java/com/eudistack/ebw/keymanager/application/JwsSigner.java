package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;

import java.security.PrivateKey;

/**
 * Single-method interface (SAM) for JWS compact serialization.
 *
 * <p>Implementations are responsible for constructing the correct JWS header (including the
 * {@code typ} value appropriate for the signing type) and producing the compact serialization
 * of the signed JWS object.</p>
 *
 * <p>The caller (use case) retains ownership of the {@code handle} and MUST close it after
 * this method returns — whether or not it succeeds — to trigger zeroization of the private
 * key material (NFR-SEC-03).</p>
 *
 * <p>Spec: EUDISTACK-407, RFC 7515 (JWS compact serialization), ADR-024.</p>
 */
@FunctionalInterface
public interface JwsSigner {

    /**
     * Produces a JWS compact serialization by signing {@code signingInput} with the private
     * key held in {@code handle}.
     *
     * @param handle       a zeroizable handle wrapping the holder's private key; the caller
     *                     will close it after this call returns
     * @param publicJwk    the holder's public key; used to include the JWK thumbprint in the
     *                     result and to embed the public key in the header when required
     * @param algorithm    the JWS algorithm to use (must match the key material in {@code handle})
     * @param signingInput the raw bytes to sign; treated as an opaque payload (EC-03)
     * @return JWS compact serialization (header.payload.signature)
     * @throws IllegalStateException if signing fails for any reason
     */
    String sign(PlaintextHandle<PrivateKey> handle,
                JwkPublic publicJwk,
                KeyAlgorithm algorithm,
                byte[] signingInput);
}
