package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.infrastructure.adapter.properties.JwtProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link Es256TokenSigner} — key loading (PEM file / ephemeral), ES256 signing and the
 * verification rules (algorithm pinning, signature, expiry, claim pass-through).
 */
class Es256TokenSignerTest {

    @TempDir
    Path tempDir;

    @Test
    void init_noKeyPathConfigured_generatesAnEphemeralKeyThatRoundTrips() {
        // Arrange
        var signer = signerWithKeyPath(null);

        // Act
        signer.init();
        var token = signer.sign(Map.of("sub", "user-1", "email", "user@example.com"));

        // Assert
        var claims = signer.verify(token);
        assertThat(claims).containsEntry("sub", "user-1").containsEntry("email", "user@example.com");
    }

    @Test
    void init_blankKeyPath_fallsBackToEphemeralKey() {
        // Arrange
        var signer = signerWithKeyPath("   ");

        // Act
        signer.init();

        // Assert
        assertThat(signer.verify(signer.sign(Map.of("sub", "user-1")))).containsEntry("sub", "user-1");
    }

    @Test
    void init_pemKeyFile_loadsTheKeyUsedToSign() throws Exception {
        // Arrange
        var pemFile = writeEcPrivateKeyPem();
        var signer = signerWithKeyPath(pemFile.toString());
        var otherSigner = signerWithKeyPath(pemFile.toString());

        // Act
        signer.init();
        otherSigner.init();
        var token = signer.sign(Map.of("sub", "user-1"));

        // Assert — a second signer loaded from the same file verifies the token
        assertThat(otherSigner.verify(token)).containsEntry("sub", "user-1");
        assertThat(SignedJWT.parse(token).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    }

    @Test
    void init_missingKeyFile_failsFast() {
        // Arrange
        var missing = tempDir.resolve("missing.pem").toString();
        var signer = signerWithKeyPath(missing);

        // Act + Assert
        assertThatThrownBy(signer::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(missing);
    }

    @Test
    void sign_numericExpAndIat_areWrittenAsEpochSecondsDates() throws Exception {
        // Arrange
        var signer = initializedEphemeralSigner();
        var iat = Instant.now().getEpochSecond();
        var exp = iat + 900;

        // Act
        var token = signer.sign(Map.of("sub", "user-1", "iat", iat, "exp", exp, "iss", "https://ebw"));

        // Assert
        var claimsSet = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claimsSet.getIssueTime().toInstant().getEpochSecond()).isEqualTo(iat);
        assertThat(claimsSet.getExpirationTime().toInstant().getEpochSecond()).isEqualTo(exp);
        assertThat(claimsSet.getIssuer()).isEqualTo("https://ebw");
    }

    @Test
    void sign_notInitialized_throwsIllegalState() {
        // Arrange
        var signer = signerWithKeyPath(null);

        // Act + Assert
        assertThatThrownBy(() -> signer.sign(Map.of("sub", "user-1")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("signer not initialized");
    }

    @Test
    void verify_notInitialized_throwsIllegalState() {
        // Arrange
        var signer = signerWithKeyPath(null);

        // Act + Assert
        assertThatThrownBy(() -> signer.verify("a.b.c"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("verifier not initialized");
    }

    @Test
    void verify_tokenWithPowersScopeAndScp_passesThemThrough() {
        // Arrange
        var signer = initializedEphemeralSigner();
        var claims = new HashMap<String, Object>();
        claims.put("sub", "user-1");
        claims.put("powers", List.of(Map.of("function", "Onboarding")));
        claims.put("scope", "openid wallet");
        claims.put("scp", List.of("wallet"));
        var token = signer.sign(claims);

        // Act
        var verified = signer.verify(token);

        // Assert
        assertThat(verified).containsKeys("powers", "scope", "scp");
        assertThat(verified.get("scope")).isEqualTo("openid wallet");
    }

    @Test
    void verify_tokenWithoutOptionalClaims_omitsThem() {
        // Arrange
        var signer = initializedEphemeralSigner();
        var token = signer.sign(Map.of("sub", "user-1"));

        // Act
        var verified = signer.verify(token);

        // Assert
        assertThat(verified).doesNotContainKeys("powers", "scope", "scp");
        assertThat(verified.get("exp")).isNull();
    }

    @Test
    void verify_expiredToken_throwsInvalidToken() {
        // Arrange
        var signer = initializedEphemeralSigner();
        var token = signer.sign(Map.of("sub", "user-1", "exp", Instant.now().minusSeconds(60).getEpochSecond()));

        // Act + Assert
        assertThatThrownBy(() -> signer.verify(token))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("JWT has expired");
    }

    @Test
    void verify_tokenSignedByAnotherKey_throwsInvalidSignature() {
        // Arrange
        var signer = initializedEphemeralSigner();
        var foreignToken = initializedEphemeralSigner().sign(Map.of("sub", "attacker"));

        // Act + Assert
        assertThatThrownBy(() -> signer.verify(foreignToken))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Invalid JWT signature");
    }

    @Test
    void verify_tokenWithAnotherAlgorithm_isRejectedBeforeSignatureCheck() throws Exception {
        // Arrange
        var signer = initializedEphemeralSigner();
        var hs256 = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .subject("user-1").expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5)))).build());
        hs256.sign(new MACSigner("an-hmac-secret-of-at-least-256-bits!".getBytes()));

        // Act + Assert
        assertThatThrownBy(() -> signer.verify(hs256.serialize()))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Unsupported JWT algorithm");
    }

    @Test
    void verify_malformedToken_throwsMalformedJwt() {
        // Arrange
        var signer = initializedEphemeralSigner();

        // Act + Assert
        assertThatThrownBy(() -> signer.verify("not-a-jwt"))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Malformed JWT");
    }

    private Es256TokenSigner initializedEphemeralSigner() {
        var signer = signerWithKeyPath(null);
        signer.init();
        return signer;
    }

    private static Es256TokenSigner signerWithKeyPath(String path) {
        return new Es256TokenSigner(new JwtProperties(path, Duration.ofMinutes(15), Duration.ofDays(7), "https://ebw"));
    }

    private Path writeEcPrivateKeyPem() throws Exception {
        var keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        var keyPair = keyGen.generateKeyPair();
        // Same layout as the dev key (PKCS#8 "PRIVATE KEY"), plus its public key so Nimbus can pair them.
        var out = new StringWriter();
        try (var writer = new JcaPEMWriter(out)) {
            writer.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
            writer.writeObject(keyPair.getPublic());
        }
        var file = tempDir.resolve("jwt-key.pem");
        Files.writeString(file, out.toString());
        return file;
    }
}
