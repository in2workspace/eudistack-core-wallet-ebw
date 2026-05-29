package com.eudistack.ebw.keymanager.e2e;

import com.eudistack.ebw.keymanager.application.GeneratedKeyPair;
import com.eudistack.ebw.keymanager.application.HolderKeyFactory;
import com.eudistack.ebw.keymanager.application.VpEnvelopeSigner;
import com.eudistack.ebw.keymanager.domain.model.KeyAlgorithm;
import com.eudistack.ebw.keymanager.domain.model.PlaintextHandle;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
 * Round-trip verification tests for VP JWS envelope signing (VC-JOSE-COSE §3.2 + OID4VP §B.1).
 *
 * <p>Signs a VP payload using {@link VpEnvelopeSigner} and verifies with the corresponding
 * public key — simulating what an OID4VP verifier would do.</p>
 *
 * <p>Covers: EUDISTACK-407 AC-02, AC-07.</p>
 */
class VpEnvelopeRoundTripIT {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final HolderKeyFactory factory = new HolderKeyFactory();
    private final VpEnvelopeSigner signer = new VpEnvelopeSigner();

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void vpEnvelope_signAndVerify_roundTrip_succeeds(KeyAlgorithm algorithm) throws Exception {
        // Given — minimal VP payload per OID4VP Appendix B.1
        byte[] payload = """
                {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],"verifiableCredential":["vcjwt.example"]}
                """.strip().getBytes();

        GeneratedKeyPair kp = factory.generate(algorithm);

        // When
        String jwsCompact;
        try (PlaintextHandle<PrivateKey> handle = kp.privateKeyHandle()) {
            jwsCompact = signer.sign(handle, kp.publicJwk(), algorithm, payload);
        }

        // Then — parse and verify
        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        // Header assertions (VC-JOSE-COSE §3.2 + technical-design §3.4.3)
        assertThat(jwsObject.getHeader().getType().getType())
                .as("typ header must be vp+jwt (VC-JOSE-COSE §3.2)")
                .isEqualTo("vp+jwt");
        // W1: cty:"vp" required per technical-design §3.4.3
        assertThat(jwsObject.getHeader().getContentType())
                .as("cty header must be 'vp' per technical-design §3.4.3")
                .isEqualTo("vp");
        assertThat(jwsObject.getHeader().getAlgorithm().getName())
                .isEqualTo(algorithm.getJwsAlgorithmName());

        // Payload must be preserved verbatim
        assertThat(jwsObject.getPayload().toBytes()).isEqualTo(payload);

        // Signature verification
        assertThat(verify(jwsObject, kp, algorithm))
                .as("VP envelope JWS signature must verify against the holder public key")
                .isTrue();
    }

    private static boolean verify(JWSObject jwsObject, GeneratedKeyPair kp, KeyAlgorithm algorithm)
            throws Exception {
        switch (algorithm) {
            case ES256, ES384 -> {
                com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
                String jwkJson = om.writeValueAsString(kp.publicJwk().claims());
                com.nimbusds.jose.jwk.JWK jwk = com.nimbusds.jose.jwk.JWK.parse(jwkJson);
                JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) jwk.toECKey().toPublicKey());
                return jwsObject.verify(verifier);
            }
            case EdDSA -> {
                Map<String, Object> claims = kp.publicJwk().claims();
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
        }
        return false;
    }
}
