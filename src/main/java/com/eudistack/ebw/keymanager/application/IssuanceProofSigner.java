package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

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
     * @param issuerIdentifier the issuer URL ({@code aud} claim)
     * @param cNonce           optional {@code c_nonce} (OID4VCI §7.2); {@code null} if omitted
     * @return the signed {@link JwsProof} in compact serialization
     * @throws IllegalStateException if header construction, signing, or serialization fails
     */
    public JwsProof sign(PlaintextHandle<PrivateKey> privateKeyHandle,
                         JwkPublic publicJwk,
                         KeyAlgorithm algorithm,
                         String issuerIdentifier,
                         @Nullable String cNonce) {
        try {
            JWSHeader header = buildHeader(algorithm, publicJwk);
            JWTClaimsSet claims = buildClaims(issuerIdentifier, cNonce);
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(buildSigner(privateKeyHandle.value(), algorithm, publicJwk));
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

    private static JWTClaimsSet buildClaims(String issuerIdentifier, @Nullable String cNonce) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience(issuerIdentifier)
                .issueTime(Date.from(Instant.now()));
        if (cNonce != null) {
            builder.claim("nonce", cNonce);
        }
        return builder.build();
    }

    private static JWSSigner buildSigner(PrivateKey key, KeyAlgorithm algorithm,
                                          JwkPublic publicJwk) throws Exception {
        return switch (algorithm) {
            case ES256, ES384 -> new ECDSASigner((ECPrivateKey) key);
            case EdDSA -> {
                // Extract 32-byte Ed25519 seed from PKCS#8 (last 32 bytes per ED25519_PKCS8_PREFIX)
                byte[] pkcs8 = key.getEncoded();
                byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
                String xB64 = (String) publicJwk.claims().get("x");
                OctetKeyPair okp = new OctetKeyPair.Builder(Curve.Ed25519, new Base64URL(xB64))
                        .d(Base64URL.encode(seed))
                        .build();
                yield new Ed25519Signer(okp);
            }
        };
    }
}