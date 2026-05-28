package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

/**
 * Produces an OID4VCI {@code jwt} proof (OID4VCI 1.0 §8.2) signed with the holder's key.
 *
 * <p>JWT structure:
 * <ul>
 *   <li>Header: {@code alg}, {@code typ=openid4vci-proof+jwt}, {@code jwk} (public key only)</li>
 *   <li>Payload: {@code aud=issuerIdentifier}, {@code iat=now}, {@code nonce=cNonce} (if present)</li>
 * </ul>
 *
 * <p>Signing is synchronous (JCA/BC crypto, no I/O). This class is a plain bean instantiated in
 * {@code KeyManagerConfiguration}.</p>
 *
 * <p>Spec: OID4VCI 1.0 §8.2, ADR-024, EUDISTACK-119.</p>
 */
public class IssuanceProofSigner {

    private static final JOSEObjectType PROOF_TYPE = new JOSEObjectType("openid4vci-proof+jwt");

    private final ObjectMapper objectMapper;

    public IssuanceProofSigner(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Signs an OID4VCI proof JWT.
     *
     * <p>The caller retains ownership of {@code privateKeyHandle} and MUST close it after this
     * call returns (whether or not it succeeds) to trigger zeroization.</p>
     *
     * @param privateKeyHandle zeroizable handle holding the signing key
     * @param publicJwk        the holder's public key, embedded in the JWT {@code jwk} header
     * @param algorithm        the JWS algorithm to use
     * @param holderId         the wallet's identifier ({@code iss} claim — OID4VCI §8.2.1.1)
     * @param issuerIdentifier the issuer URL ({@code aud} claim)
     * @param cNonce           optional {@code c_nonce} (OID4VCI §7.2); {@code null} if omitted
     * @return the signed {@link JwsProof} in compact serialization
     * @throws IllegalStateException if header construction, signing, or serialization fails
     */
    public JwsProof sign(PlaintextHandle<PrivateKey> privateKeyHandle,
                         JwkPublic publicJwk,
                         KeyAlgorithm algorithm,
                         String holderId,
                         String issuerIdentifier,
                         @Nullable String cNonce) {
        try {
            JWSHeader header = buildHeader(algorithm, publicJwk);
            JWTClaimsSet claims = buildClaims(holderId, issuerIdentifier, cNonce);
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(buildSigner(privateKeyHandle.value(), algorithm));
            return new JwsProof(jwt.serialize(), algorithm);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign OID4VCI proof JWT", e);
        }
    }

    private JWSHeader buildHeader(KeyAlgorithm algorithm, JwkPublic publicJwk) throws Exception {
        String jwkJson = objectMapper.writeValueAsString(publicJwk.claims());
        JWK jwk = JWK.parse(jwkJson);
        return new JWSHeader.Builder(JWSAlgorithm.parse(algorithm.getJwsAlgorithmName()))
                .type(PROOF_TYPE)
                .jwk(jwk.toPublicJWK())
                .build();
    }

    private static JWTClaimsSet buildClaims(String holderId,
                                             String issuerIdentifier,
                                             @Nullable String cNonce) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(holderId)
                .audience(issuerIdentifier)
                .issueTime(Date.from(Instant.now()));
        if (cNonce != null) {
            builder.claim("nonce", cNonce);
        }
        return builder.build();
    }

    private static JWSSigner buildSigner(PrivateKey key, KeyAlgorithm algorithm) {
        return switch (algorithm) {
            case ES256, ES384 -> {
                try {
                    yield new ECDSASigner((ECPrivateKey) key);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to build ECDSA signer", e);
                }
            }
            case EdDSA -> buildEdDsaSignerBC(key);
        };
    }

    /**
     * BouncyCastle-based Ed25519 JWSSigner. Avoids a dependency on Google Tink, which is
     * an optional transitive dependency of nimbus-jose-jwt that is not present in this module.
     */
    private static JWSSigner buildEdDsaSignerBC(PrivateKey key) {
        return new JWSSigner() {
            private final JCAContext jcaContext = new JCAContext();

            @Override
            public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
                try {
                    Signature sig = Signature.getInstance(
                            "Ed25519", BouncyCastleProvider.PROVIDER_NAME);
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