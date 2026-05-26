package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;

import java.security.PrivateKey;

/**
 * The result of a key-pair generation: a zeroizable private key handle and its
 * corresponding public JWK.
 *
 * <p>The caller is responsible for closing the {@code privateKeyHandle} after use to
 * trigger the zeroizer. Use try-with-resources whenever possible.</p>
 *
 * <p>Spec: EUDISTACK-119, ADR-024, ADR-099.</p>
 *
 * @param privateKeyHandle a {@link PlaintextHandle} wrapping the generated {@link PrivateKey}
 * @param publicJwk        the public key as a JWK value object
 */
public record GeneratedKeyPair(
        PlaintextHandle<PrivateKey> privateKeyHandle,
        JwkPublic publicJwk
) {
}