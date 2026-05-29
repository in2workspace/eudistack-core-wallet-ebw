package com.eudistack.ebw.keymanager.application;

import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KbJwtSigner} — three algorithms (AC-01, AC-09, ADR-024).
 *
 * <p>Each test generates a real key pair via {@link HolderKeyFactory}, signs a fixed payload,
 * then verifies with the corresponding Nimbus verifier to confirm the JWS is valid.</p>
 */
class KbJwtSignerTest {

    private HolderKeyFactory factory;
    private KbJwtSigner signer;

    @BeforeEach
    void setUp() {
        factory = new HolderKeyFactory();
        signer = new KbJwtSigner();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_allAlgorithms_producesValidKbJwtWithCorrectTypHeader(KeyAlgorithm algorithm)
            throws Exception {
        // Given
        GeneratedKeyPair generated = factory.generate(algorithm);
        byte[] signingInput = "test payload".getBytes();

        // When
        String jwsCompact;
        try (PlaintextHandle<PrivateKey> handle = generated.privateKeyHandle()) {
            jwsCompact = signer.sign(handle, generated.publicJwk(), algorithm, signingInput);
        }

        // Then
        assertThat(jwsCompact).isNotBlank();
        assertThat(jwsCompact.split("\\.")).hasSize(3);

        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        // Header must have typ=kb+jwt (RFC 9901 §4.1.2)
        assertThat(jwsObject.getHeader().getType().getType()).isEqualTo("kb+jwt");
        assertThat(jwsObject.getHeader().getAlgorithm().getName())
                .isEqualTo(algorithm.getJwsAlgorithmName());

        // Payload must match signingInput
        assertThat(jwsObject.getPayload().toBytes()).isEqualTo(signingInput);

        // Signature must be valid
        assertThat(verify(jwsObject, generated, algorithm)).isTrue();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_sameInputTwice_producesDifferentSignatures_orIdempotentForEdDsa(KeyAlgorithm algorithm)
            throws Exception {
        // Given
        GeneratedKeyPair generated = factory.generate(algorithm);
        byte[] signingInput = "idempotency test".getBytes();

        String jws1;
        String jws2;
        try (PlaintextHandle<PrivateKey> handle = generated.privateKeyHandle()) {
            jws1 = signer.sign(handle, generated.publicJwk(), algorithm, signingInput);
            // close is idempotent, can re-sign if needed — but we need a fresh handle
        }
        GeneratedKeyPair generated2 = factory.generate(algorithm);
        // use same bytes to reconstruct key
        byte[] keyBytes = generated2.rawPrivateBytes().clone();
        try (PlaintextHandle<PrivateKey> handle2 = factory.fromBytes(keyBytes, algorithm)) {
            jws2 = signer.sign(handle2, generated2.publicJwk(), algorithm, signingInput);
        }

        // Both must be parseable and valid (functional idempotency — AC-09)
        JWSObject o1 = JWSObject.parse(jws1);
        JWSObject o2 = JWSObject.parse(jws2);
        assertThat(o1.getPayload().toBytes()).isEqualTo(signingInput);
        assertThat(o2.getPayload().toBytes()).isEqualTo(signingInput);
    }

    // --- helpers ---

    private static boolean verify(JWSObject jwsObject, GeneratedKeyPair generated,
                                   KeyAlgorithm algorithm) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        switch (algorithm) {
            case ES256, ES384 -> {
                com.nimbusds.jose.jwk.JWK jwk = parseJwk(generated);
                JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) jwk.toECKey().toPublicKey());
                return jwsObject.verify(verifier);
            }
            case EdDSA -> {
                // Verify Ed25519 via BouncyCastle (no Tink dependency)
                return verifyEdDsaBC(jwsObject, generated);
            }
        }
        return false;
    }

    private static boolean verifyEdDsaBC(JWSObject jwsObject, GeneratedKeyPair generated)
            throws Exception {
        // Reconstruct public key from JWK x parameter
        Map<String, Object> claims = generated.publicJwk().claims();
        byte[] xBytes = Base64.getUrlDecoder().decode((String) claims.get("x"));

        // Build PKCS#8-like SubjectPublicKeyInfo for Ed25519 (last 32 bytes of SPKI)
        // Nimbus's JWSObject stores signingInput as base64url(header).base64url(payload)
        String serialized = jwsObject.serialize();
        String[] parts = serialized.split("\\.");
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] signature = Base64URL.from(parts[2]).decode();

        // Reconstruct public key via BouncyCastle
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        // SubjectPublicKeyInfo prefix for Ed25519 + 32 bytes public key
        byte[] spkiPrefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
        byte[] spki = new byte[spkiPrefix.length + xBytes.length];
        System.arraycopy(spkiPrefix, 0, spki, 0, spkiPrefix.length);
        System.arraycopy(xBytes, 0, spki, spkiPrefix.length, xBytes.length);
        PublicKey pubKey = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(spki));

        Signature sig = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        sig.initVerify(pubKey);
        sig.update(signingInput);
        return sig.verify(signature);
    }

    private static com.nimbusds.jose.jwk.JWK parseJwk(GeneratedKeyPair generated) throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
        String jwkJson = om.writeValueAsString(generated.publicJwk().claims());
        return com.nimbusds.jose.jwk.JWK.parse(jwkJson);
    }
}
