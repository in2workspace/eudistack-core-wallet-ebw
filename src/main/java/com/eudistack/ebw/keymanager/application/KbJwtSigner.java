package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

/**
 * Produces a key-binding JWT (RFC 9901 §4.1.2) using the holder's private key.
 *
 * <p>JWS header: {@code {"alg": "<alg>", "typ": "kb+jwt"}}.</p>
 *
 * <p>The {@code signingInput} is treated as an opaque byte payload — the EBW does NOT parse
 * its structure (EC-03). The consumer (EUDISTACK-8) is responsible for assembling a valid
 * KB-JWT payload ({@code sd_hash}, {@code nonce}, {@code aud}, {@code iat}).</p>
 *
 * <p>Three algorithms are supported per ADR-024: ES256, ES384 (ECDSA via BouncyCastle),
 * EdDSA (Ed25519 via BouncyCastle). The algorithm switch reuses the same pattern as
 * {@link IssuanceProofSigner} — specifically the BouncyCastle-based Ed25519 signer
 * to avoid Tink dependency issues.</p>
 *
 * <p>Spec: RFC 9901 §4.1.2, EUDISTACK-407 AC-01, AC-09, ADR-024.</p>
 */
public class KbJwtSigner implements JwsSigner {

    private static final JOSEObjectType KB_JWT_TYPE = new JOSEObjectType("kb+jwt");

    @Override
    public String sign(PlaintextHandle<PrivateKey> handle,
                       JwkPublic publicJwk,
                       KeyAlgorithm algorithm,
                       byte[] signingInput) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm.getJwsAlgorithmName()))
                    .type(KB_JWT_TYPE)
                    .build();
            JWSObject jwsObject = new JWSObject(header, new Payload(signingInput));
            jwsObject.sign(buildSigner(handle.value(), algorithm));
            return jwsObject.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to produce kb+jwt for algorithm " + algorithm, e);
        }
    }

    private static JWSSigner buildSigner(PrivateKey key, KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256, ES384 -> {
                try {
                    yield new ECDSASigner((ECPrivateKey) key);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to build ECDSA signer for " + algorithm, e);
                }
            }
            case EdDSA -> buildEdDsaSignerBC(key);
        };
    }

    /**
     * BouncyCastle-based Ed25519 JWSSigner — delegates to {@link JwsSignerHelper#buildEdDsaSignerBC}.
     * Kept as a package-private method for tests that directly reference this class.
     */
    static JWSSigner buildEdDsaSignerBC(PrivateKey key) {
        return JwsSignerHelper.buildEdDsaSignerBC(key);
    }
}
