package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.JwkPublic;
import com.eudistack.ebw.keymanager.domain.model.JwsProof;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceProofSignerTest {

    private static final String HOLDER_ID = "holder-abc-123";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String C_NONCE = "test-nonce-abc";

    private HolderKeyFactory factory;
    private IssuanceProofSigner signer;

    @BeforeEach
    void setUp() {
        factory = new HolderKeyFactory();
        signer = new IssuanceProofSigner(new ObjectMapper());
    }

    // --- successful signing for all supported algorithms ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_producesValidCompactJwt(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        PlaintextHandle<PrivateKey> handle = generated.privateKeyHandle();
        JwkPublic publicJwk = generated.publicJwk();

        JwsProof proof = signer.sign(handle, publicJwk, algorithm, HOLDER_ID, ISSUER, C_NONCE);

        assertThat(proof).isNotNull();
        assertThat(proof.algorithm()).isEqualTo(algorithm);
        assertThat(proof.compactSerialization()).matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+");
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_jwtHeader_hasCorrectTypAndAlg(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getHeader().getType().toString()).isEqualTo("openid4vci-proof+jwt");
        assertThat(jwt.getHeader().getAlgorithm().getName())
                .isEqualTo(algorithm.getJwsAlgorithmName());
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_jwtHeader_containsPublicJwk_noPrivateFields(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());
        String jwkJson = jwt.getHeader().getJWK().toJSONString();

        assertThat(jwkJson).doesNotContain("\"d\""); // no private key field
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_jwtPayload_hasAudAndIat(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly(ISSUER);
        assertThat(jwt.getJWTClaimsSet().getIssueTime()).isNotNull();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_jwtPayload_hasIssEqualToHolderId(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getJWTClaimsSet().getIssuer())
                .as("iss claim must equal holderId (OID4VCI §8.2.1.1)")
                .isEqualTo(HOLDER_ID);
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_withCNonce_jwtPayload_containsNonce(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo(C_NONCE);
    }

    // --- EC-05: cNonce absent means nonce claim must be absent ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_withoutCNonce_jwtPayload_hasNoNonceClaim(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, null);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getJWTClaimsSet().getStringClaim("nonce"))
                .as("nonce claim must be absent when cNonce is null (EC-05)")
                .isNull();
    }

    // --- signature is verifiable ---

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_jwtSignature_hasNonEmptySignatureBytes(KeyAlgorithm algorithm) throws Exception {
        GeneratedKeyPair generated = factory.generate(algorithm);
        JwsProof proof = signer.sign(
                generated.privateKeyHandle(), generated.publicJwk(), algorithm, HOLDER_ID, ISSUER, C_NONCE);

        SignedJWT jwt = SignedJWT.parse(proof.compactSerialization());

        assertThat(jwt.getSignature().decode()).isNotEmpty();
        assertThat(jwt.getState()).isEqualTo(JWSObject.State.SIGNED);
    }
}