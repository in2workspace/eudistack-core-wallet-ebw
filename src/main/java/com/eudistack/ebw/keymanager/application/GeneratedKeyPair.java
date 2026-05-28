package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;

import java.security.PrivateKey;

/**
 * The result of a key-pair generation: a zeroizable private key handle, its corresponding
 * public JWK, and the raw private key bytes for DB persistence.
 *
 * <p>{@code rawPrivateBytes} is the SAME array that the handle's zeroizer will fill with
 * zeros on {@link PlaintextHandle#close()}. The use case passes this reference to
 * {@link com.eudistack.ebw.keymanager.domain.model.HolderKey} for persistence, then closes the
 * handle after signing — at which point the in-memory plaintext is cleared (ADR-099).</p>
 *
 * <p>The caller is responsible for closing the {@code privateKeyHandle} after use. Use
 * try-finally whenever possible to guarantee zeroization even on error.</p>
 *
 * <p>Spec: EUDISTACK-119, ADR-024, ADR-099.</p>
 *
 * @param privateKeyHandle a {@link PlaintextHandle} wrapping the generated {@link PrivateKey}
 * @param publicJwk        the public key as a JWK value object
 * @param rawPrivateBytes  raw private key bytes (scalar for EC; seed for EdDSA); ownership
 *                         is transferred — the array is zeroed when the handle is closed
 */
public record GeneratedKeyPair(
        PlaintextHandle<PrivateKey> privateKeyHandle,
        JwkPublic publicJwk,
        byte[] rawPrivateBytes
) {
}