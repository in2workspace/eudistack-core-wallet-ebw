package com.eudistack.ebw.infrastructure.adapter.webauthn;

import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.support.SoftwareAuthenticator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WebAuthn4jVerifierTest {

    private static final String RP_ID = "sandbox.stg.eudistack.net";
    private static final String ORIGIN = "https://sandbox.stg.eudistack.net";
    private static final RelyingPartySettings RP = new RelyingPartySettings(RP_ID, "EUDIStack Wallet", List.of(ORIGIN));
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final WebAuthn4jVerifier verifier = new WebAuthn4jVerifier();
    private SoftwareAuthenticator authenticator;
    private byte[] userHandle;

    @BeforeEach
    void setUp() {
        authenticator = new SoftwareAuthenticator(ORIGIN);
        userHandle = random(32);
    }

    @Test
    void verifyRegistration_validResponse_returnsCredentialRecord() throws Exception {
        var challenge = random(32);

        var result = verifier.verifyRegistration(registrationJson(challenge), challenge, RP);

        assertThat(result.credentialId()).isEqualTo(authenticator.credentialIdBase64Url());
        assertThat(result.attestedCredentialData()).isNotEmpty();
        assertThat(result.uvInitialized()).isTrue();
        assertThat(result.backupEligible()).isTrue();
        assertThat(result.backupState()).isTrue();
        assertThat(result.attestationFormat()).isEqualTo("none");
        assertThat(result.transports()).containsExactly("hybrid", "internal");
        assertThat(result.aaguid()).isNull();
    }

    @Test
    void verifyRegistration_otherChallenge_throws() throws Exception {
        var json = registrationJson(random(32));

        assertThatThrownBy(() -> verifier.verifyRegistration(json, random(32), RP))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("BadChallenge");
    }

    @Test
    void verifyRegistration_foreignOrigin_throws() throws Exception {
        authenticator.withOrigin("https://evil.example.com");
        var challenge = random(32);
        var json = registrationJson(challenge);

        assertThatThrownBy(() -> verifier.verifyRegistration(json, challenge, RP))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("BadOrigin");
    }

    @Test
    void verifyRegistration_withoutUserVerification_throws() throws Exception {
        authenticator.withUserVerified(false);
        var challenge = random(32);
        var json = registrationJson(challenge);

        assertThatThrownBy(() -> verifier.verifyRegistration(json, challenge, RP))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("UserNotVerified");
    }

    @Test
    void verifyAuthentication_validAssertion_returnsNewCounter() throws Exception {
        var passkey = registeredPasskey();
        var challenge = random(32);

        var result = verifier.verifyAuthentication(authenticationJson(challenge), challenge, RP, passkey);

        assertThat(result.signCount()).isEqualTo(1);
        assertThat(result.userVerified()).isTrue();
        assertThat(result.backupState()).isTrue();
    }

    @Test
    void readAssertion_validAssertion_returnsCredentialIdAndUserHandle() throws Exception {
        registeredPasskey();

        var assertion = verifier.readAssertion(authenticationJson(random(32)));

        assertThat(assertion.credentialId()).isEqualTo(authenticator.credentialIdBase64Url());
        assertThat(assertion.userHandle()).isEqualTo(userHandle);
    }

    @Test
    void verifyAuthentication_counterNotAdvancing_throws() throws Exception {
        authenticator.withSignCount(10);
        var passkey = registeredPasskey();
        authenticator.withSignCount(3);
        var challenge = random(32);
        var json = authenticationJson(challenge);

        assertThatThrownBy(() -> verifier.verifyAuthentication(json, challenge, RP, passkey))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("MaliciousCounterValue");
    }

    @Test
    void verifyAuthentication_bothCountersZero_accepts() throws Exception {
        authenticator.withSignCountStep(0);
        var passkey = registeredPasskey();
        var challenge = random(32);

        var result = verifier.verifyAuthentication(authenticationJson(challenge), challenge, RP, passkey);

        assertThat(result.signCount()).isZero();
    }

    @Test
    void verifyAuthentication_backupEligibleFlipped_throws() throws Exception {
        authenticator.withBackupEligible(false).withBackupState(false);
        var passkey = registeredPasskey();
        authenticator.withBackupEligible(true);
        var challenge = random(32);
        var json = authenticationJson(challenge);

        assertThatThrownBy(() -> verifier.verifyAuthentication(json, challenge, RP, passkey))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("BackupEligible");
    }

    @Test
    void verifyAuthentication_signatureOfAnotherKey_throws() throws Exception {
        var passkey = registeredPasskey();
        var other = new SoftwareAuthenticator(ORIGIN).withUserHandle(userHandle);
        var challenge = random(32);
        @SuppressWarnings("unchecked")
        Map<String, Object> forged = other.authenticate(requestOptions(challenge));
        forged.put("id", passkey.getCredentialId());
        forged.put("rawId", passkey.getCredentialId());
        var json = objectMapper.writeValueAsString(forged);

        assertThatThrownBy(() -> verifier.verifyAuthentication(json, challenge, RP, passkey))
                .isInstanceOf(WebAuthnVerificationException.class)
                .hasMessageContaining("BadSignature");
    }

    @Test
    void readAssertion_malformedJson_throws() {
        assertThatThrownBy(() -> verifier.readAssertion("{not json"))
                .isInstanceOf(WebAuthnVerificationException.class);
    }

    // ------------------------------------------------------------------ helpers

    private UserPasskey registeredPasskey() throws Exception {
        var challenge = random(32);
        VerifiedPasskeyRegistration registration = verifier.verifyRegistration(registrationJson(challenge), challenge, RP);
        return UserPasskey.register(UUID.randomUUID(), registration, true, "Passkey", null);
    }

    private String registrationJson(byte[] challenge) throws Exception {
        Map<String, Object> creationOptions = Map.of(
                "rp", Map.of("id", RP_ID, "name", "EUDIStack Wallet"),
                "user", Map.of("id", B64.encodeToString(userHandle), "name", "ana@example.com",
                        "displayName", "ana@example.com"),
                "challenge", B64.encodeToString(challenge));
        return objectMapper.writeValueAsString(authenticator.register(creationOptions));
    }

    private String authenticationJson(byte[] challenge) throws Exception {
        return objectMapper.writeValueAsString(authenticator.authenticate(requestOptions(challenge)));
    }

    private static Map<String, Object> requestOptions(byte[] challenge) {
        return Map.of("challenge", B64.encodeToString(challenge), "rpId", RP_ID);
    }

    private static byte[] random(int length) {
        var bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
