package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.util.Set;

/**
 * Produces a VP JWS envelope (VC-JOSE-COSE §3.2 + OID4VP Appendix B.1) using the holder's
 * private key.
 *
 * <p>JWS header: {@code {"alg": "<alg>", "typ": "vp+jwt"}}.</p>
 *
 * <p>The {@code signingInput} is treated as an opaque byte payload — the EBW does NOT parse
 * its structure (EC-03). The consumer (EUDISTACK-6/7) is responsible for assembling a valid
 * VP payload including {@code @context}, {@code type}, and {@code verifiableCredential} fields.</p>
 *
 * <p>Three algorithms are supported per ADR-024: ES256, ES384, EdDSA.
 * The algorithm switch mirrors {@link KbJwtSigner} — BouncyCastle for Ed25519.</p>
 *
 * <p>Spec: VC-JOSE-COSE §3.2, OID4VP 1.0 Appendix B.1, EUDISTACK-407 AC-02, AC-09, ADR-024.</p>
 */
public class VpEnvelopeSigner implements JwsSigner {

    private static final JOSEObjectType VP_JWT_TYPE = new JOSEObjectType("vp+jwt");

    @Override
    public String sign(PlaintextHandle<PrivateKey> handle,
                       JwkPublic publicJwk,
                       KeyAlgorithm algorithm,
                       byte[] signingInput) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm.getJwsAlgorithmName()))
                    .type(VP_JWT_TYPE)
                    .build();
            JWSObject jwsObject = new JWSObject(header, new Payload(signingInput));
            jwsObject.sign(buildSigner(handle.value(), algorithm));
            return jwsObject.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to produce vp+jwt for algorithm " + algorithm, e);
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
     * BouncyCastle-based Ed25519 JWSSigner — mirrors the pattern from {@link KbJwtSigner}.
     */
    static JWSSigner buildEdDsaSignerBC(PrivateKey key) {
        return new JWSSigner() {
            private final JCAContext jcaContext = new JCAContext();

            @Override
            public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
                try {
                    Signature sig = Signature.getInstance(
                            "Ed25519", org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
                    sig.initSign(key);
                    sig.update(signingInput);
                    return Base64URL.encode(sig.sign());
                } catch (Exception e) {
                    throw new JOSEException("Ed25519 sign failed (BouncyCastle)", e);
                }
            }

            @Override
            public Set<JWSAlgorithm> supportedJWSAlgorithms() {
                return Set.of(JWSAlgorithm.EdDSA);
            }

            @Override
            public JCAContext getJCAContext() {
                return jcaContext;
            }
        };
    }
}
