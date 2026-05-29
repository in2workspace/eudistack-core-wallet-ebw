package com.eudistack.ebw.keymanager.e2e;

import com.eudistack.ebw.keymanager.application.GeneratedKeyPair;
import com.eudistack.ebw.keymanager.application.HolderKeyFactory;
import com.eudistack.ebw.keymanager.application.KbJwtSigner;
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
 * Round-trip verification tests for KB-JWT signing (RFC 9901 §4.1.2).
 *
 * <p>Signs a payload using {@link KbJwtSigner} and immediately verifies the JWS
 * using the corresponding public key — simulating what a verifier (DOME) would do.</p>
 *
 * <p>Covers: EUDISTACK-407 AC-01, AC-07.</p>
 *
 * <p>Note: full E2E round-trip against a live DOME verifier is executed post-merge in STG
 * (not in CI). See k6 scripts in {@code src/test/resources/perf/}.</p>
 */
class KbJwtRoundTripIT {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final HolderKeyFactory factory = new HolderKeyFactory();
    private final KbJwtSigner signer = new KbJwtSigner();

    @ParameterizedTest
    @EnumSource(KeyAlgorithm.class)
    void kbJwt_signAndVerify_roundTrip_succeeds(KeyAlgorithm algorithm) throws Exception {
        // Given — payload as specified in RFC 9901 §B.3 (sd_hash + nonce + aud + iat)
        byte[] payload = """
                {"sd_hash":"abc123","nonce":"n-0S6_WzA2Mj","aud":"https://verifier.example.org","iat":1720000000}
                """.strip().getBytes();

        GeneratedKeyPair kp = factory.generate(algorithm);

        // When
        String jwsCompact;
        try (PlaintextHandle<PrivateKey> handle = kp.privateKeyHandle()) {
            jwsCompact = signer.sign(handle, kp.publicJwk(), algorithm, payload);
        }

        // Then — parse and verify
        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        // Header assertions (RFC 9901 §4.1.2)
        assertThat(jwsObject.getHeader().getType().getType())
                .as("typ header must be kb+jwt (RFC 9901 §4.1.2)")
                .isEqualTo("kb+jwt");
        assertThat(jwsObject.getHeader().getAlgorithm().getName())
                .isEqualTo(algorithm.getJwsAlgorithmName());

        // Payload must be preserved verbatim
        assertThat(jwsObject.getPayload().toBytes()).isEqualTo(payload);

        // Signature verification using reference verifier
        assertThat(verify(jwsObject, kp, algorithm))
                .as("JWS signature must verify against the holder public key")
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
