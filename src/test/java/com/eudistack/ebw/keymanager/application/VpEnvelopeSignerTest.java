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
 * Unit tests for {@link VpEnvelopeSigner} — three algorithms (AC-02, AC-09, ADR-024).
 *
 * <p>Each test generates a real key pair, signs, then verifies to confirm the JWS is valid
 * with the correct {@code typ=vp+jwt} header.</p>
 */
class VpEnvelopeSignerTest {

    private HolderKeyFactory factory;
    private VpEnvelopeSigner signer;

    @BeforeEach
    void setUp() {
        factory = new HolderKeyFactory();
        signer = new VpEnvelopeSigner();
    }

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void sign_allAlgorithms_producesValidVpJwtWithCorrectTypHeader(KeyAlgorithm algorithm)
            throws Exception {
        // Given
        GeneratedKeyPair generated = factory.generate(algorithm);
        byte[] signingInput = "{\"vp\": {}}".getBytes();

        // When
        String jwsCompact;
        try (PlaintextHandle<PrivateKey> handle = generated.privateKeyHandle()) {
            jwsCompact = signer.sign(handle, generated.publicJwk(), algorithm, signingInput);
        }

        // Then
        assertThat(jwsCompact).isNotBlank();
        assertThat(jwsCompact.split("\\.")).hasSize(3);

        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        // Header must have typ=vp+jwt (VC-JOSE-COSE §3.2)
        assertThat(jwsObject.getHeader().getType().getType()).isEqualTo("vp+jwt");
        // W1: cty:"vp" required per technical-design §3.4.3
        assertThat(jwsObject.getHeader().getContentType())
                .as("cty header must be 'vp' per technical-design §3.4.3")
                .isEqualTo("vp");
        assertThat(jwsObject.getHeader().getAlgorithm().getName())
                .isEqualTo(algorithm.getJwsAlgorithmName());

        // Payload must match signingInput
        assertThat(jwsObject.getPayload().toBytes()).isEqualTo(signingInput);

        // Signature must be valid
        assertThat(verify(jwsObject, generated, algorithm)).isTrue();
    }

    // --- helpers (same pattern as KbJwtSignerTest) ---

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
                return verifyEdDsaBC(jwsObject, generated);
            }
        }
        return false;
    }

    private static boolean verifyEdDsaBC(JWSObject jwsObject, GeneratedKeyPair generated)
            throws Exception {
        Map<String, Object> claims = generated.publicJwk().claims();
        byte[] xBytes = Base64.getUrlDecoder().decode((String) claims.get("x"));

        String serialized = jwsObject.serialize();
        String[] parts = serialized.split("\\.");
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] signature = Base64URL.from(parts[2]).decode();

        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
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
