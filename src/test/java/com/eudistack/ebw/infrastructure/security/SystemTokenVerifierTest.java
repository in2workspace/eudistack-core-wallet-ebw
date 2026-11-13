package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.verifier.VerifierJwksClient;
import com.eudistack.ebw.infrastructure.adapter.verifier.VerifierUnavailableException;
import com.eudistack.ebw.support.TestSystemTokens;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link SystemTokenVerifier} (AC-02, ES-04, ES-05, EC-14, design AD-9). */
@ExtendWith(MockitoExtension.class)
class SystemTokenVerifierTest {

    private static final String ISSUER = "https://sandbox.stg.eudistack.net/verifier";
    private static final String TENANT = "sandbox";

    @Mock private VerifierJwksClient jwksClient;

    private final TestSystemTokens verifierKeys = new TestSystemTokens();
    private SystemTokenVerifier tokenVerifier;

    @BeforeEach
    void setUp() {
        tokenVerifier = new SystemTokenVerifier(jwksClient);
        lenient().when(jwksClient.keys()).thenReturn(Mono.just(verifierKeys.publicJwks()));
    }

    private void expectRejectedFor(String token, String reason) {
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(SystemTokenRejectedException.class)
                        .extracting("type", "reason").containsExactly("invalid_token", reason))
                .verify();
    }

    /** A token with the claims of a valid one, signed with {@code alg} by {@code key}, published by the Verifier. */
    private String tokenSignedWith(JWSAlgorithm alg, JWK key, JWSSigner signer) throws Exception {
        JWTClaimsSet claims = SignedJWT.parse(verifierKeys.token(ISSUER, TENANT)).getJWTClaimsSet();
        var jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(key.getKeyID()).build(), claims);
        jwt.sign(signer);
        lenient().when(jwksClient.keys()).thenReturn(Mono.just(new JWKSet(List.of(
                verifierKeys.publicJwks().getKeys().getFirst(), key.toPublicJWK()))));
        return jwt.serialize();
    }

    private void expectRejected(String token, String type) {
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(SystemTokenRejectedException.class)
                        .extracting("type").isEqualTo(type))
                .verify();
    }

    @Test
    void verify_tenantAdministratorMachine_returnsTheCaller() {
        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(verifierKeys.token(ISSUER, TENANT), TENANT, ISSUER + "/"))
                .assertNext(caller -> assertThat(caller.id()).isEqualTo("portal-machine.example.org"))
                .verifyComplete();
    }

    @Test
    void verify_powerDomainAndTenantIgnoreCase_isAccepted() {
        // Arrange
        var token = verifierKeys.token(ISSUER, "SANDBOX", "LEARCredentialMachine",
                List.of(Map.of("type", "organization", "domain", "SandBox", "function", "Onboarding",
                        "action", "Execute")), Instant.now().plusSeconds(60));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }

    @Test
    void verify_otherIssuer_isInvalidTokenWithoutReadingKeys() {
        // Act
        expectRejected(verifierKeys.token("https://evil.example/verifier", TENANT), "invalid_token");

        // Assert
        verify(jwksClient, never()).keys();
    }

    @Test
    void verify_sessionTokenOfThisService_isInvalidToken() {
        // Arrange: same layout, other issuer and key, like an access token of a wallet session
        var sessionToken = new TestSystemTokens().token("eudistack-ebw", TENANT);

        // Act + Assert
        expectRejected(sessionToken, "invalid_token");
    }

    @Test
    void verify_signedByAnotherKeyWithSameKid_isInvalidToken() {
        // Arrange
        var impostor = new TestSystemTokens(verifierKeys.kid());

        // Act + Assert
        expectRejected(impostor.token(ISSUER, TENANT), "invalid_token");
    }

    @Test
    void verify_expired_isInvalidToken() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().minusSeconds(1)), "invalid_token");
    }

    @Test
    void verify_tokenOfAnotherTenant_isInvalidToken() {
        expectRejected(verifierKeys.token(ISSUER, "kpmg", "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60)), "invalid_token");
    }

    @Test
    void verify_notAMachineCredential_isInsufficientPermission() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialEmployee",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60)),
                "insufficient_permission");
    }

    @Test
    void verify_machineWithoutOnboardingPower_isInsufficientPermission() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("type", "Domain", "domain", TENANT, "function", "ProductOffering",
                        "action", List.of("Create"))), Instant.now().plusSeconds(60)), "insufficient_permission");
    }

    @Test
    void verify_organizationAdministratorPower_isInsufficientPermission() {
        // Arrange: AD-9, the same power with type domain is an organization administrator (Issuer matrix)
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("type", "domain", "domain", TENANT, "function", "Onboarding",
                        "action", List.of("Execute"))), Instant.now().plusSeconds(60)), "insufficient_permission");
    }

    @Test
    void verify_powerTypeWithOtherCase_isInsufficientPermission() {
        // Arrange: type is compared exactly, as in the Issuer
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("type", "Organization", "domain", TENANT, "function", "Onboarding",
                        "action", "Execute")), Instant.now().plusSeconds(60)), "insufficient_permission");
    }

    @Test
    void verify_powerWithoutType_isInsufficientPermission() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("domain", TENANT, "function", "Onboarding", "action", "Execute")),
                Instant.now().plusSeconds(60)), "insufficient_permission");
    }

    @Test
    void verify_administratorOfAnotherTenant_isInsufficientPermission() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower("kpmg")), Instant.now().plusSeconds(60)),
                "insufficient_permission");
    }

    @Test
    void verify_sdJwtMachineCredential_isAccepted() {
        // Arrange: EC-14, an SD-JWT machine credential names its configuration id
        var token = verifierKeys.token(ISSUER, TENANT, "learcredential.machine.sd.1",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }

    @Test
    void verify_otherSdJwtCredential_isInsufficientPermission() {
        expectRejected(verifierKeys.token(ISSUER, TENANT, "learcredential.employee.sd.1",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60)),
                "insufficient_permission");
    }

    @Test
    void verify_tenantWithEnvironmentSuffix_isAccepted() {
        // Arrange: EC-14, the Verifier's client registration of STG names the tenant sandbox-stg
        var token = verifierKeys.token(ISSUER, "sandbox-stg", "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }

    @Test
    void verify_tenantWithSuffixOfAnotherTenant_isInvalidToken() {
        expectRejected(verifierKeys.token(ISSUER, "kpmg-stg", "LEARCredentialMachine",
                List.of(TestSystemTokens.onboardingPower(TENANT)), Instant.now().plusSeconds(60)), "invalid_token");
    }

    @Test
    void verify_powerWithTmfAliases_isAccepted() {
        // Arrange: EC-14, the fields of the power come as their tmf_ aliases
        var token = verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("tmf_type", "organization", "tmf_domain", TENANT, "tmf_function", "Onboarding",
                        "tmf_action", List.of("Execute"))), Instant.now().plusSeconds(60));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }

    @Test
    void verify_powerWhoseFieldAndAliasDiffer_isInsufficientPermission() {
        // Arrange: the field says this tenant and its alias another one, so the power is ignored
        expectRejected(verifierKeys.token(ISSUER, TENANT, "LEARCredentialMachine",
                List.of(Map.of("type", "organization", "domain", TENANT, "tmf_domain", "kpmg",
                        "function", "Onboarding", "action", "Execute")), Instant.now().plusSeconds(60)),
                "insufficient_permission");
    }

    @Test
    void verify_malformedOrMissing_isInvalidToken() {
        expectRejected("not-a-jwt", "invalid_token");
        expectRejected(null, "invalid_token");
    }

    @Test
    void verify_unknownKid_reloadsOnceAndAcceptsTheRotatedKey() {
        // Arrange
        var rotated = new TestSystemTokens();
        when(jwksClient.reload()).thenReturn(Mono.just(rotated.publicJwks()));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(rotated.token(ISSUER, TENANT), TENANT, ISSUER))
                .expectNextCount(1)
                .verifyComplete();
        verify(jwksClient).reload();
    }

    @Test
    void verify_unknownKidAfterReload_isInvalidToken() {
        // Arrange
        when(jwksClient.reload()).thenReturn(Mono.just(verifierKeys.publicJwks()));

        // Act + Assert
        expectRejected(new TestSystemTokens().token(ISSUER, TENANT), "invalid_token");
    }

    @Test
    void verify_keysUnavailable_propagatesVerifierUnavailable() {
        // Arrange
        when(jwksClient.keys()).thenReturn(Mono.error(new VerifierUnavailableException("down")));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(verifierKeys.token(ISSUER, TENANT), TENANT, ISSUER))
                .expectError(VerifierUnavailableException.class)
                .verify(Duration.ofSeconds(5));
    }

    // ------------------------------------------------------------------ F3-n: ES256 only, nbf and iat

    @Test
    void verify_rs256WithAnRsaKeyOfTheVerifier_isInvalidTokenWithoutReadingKeys() throws Exception {
        // Arrange: SEC-04, the Verifier signs its access tokens with ES256 only
        var rsa = new RSAKeyGenerator(2048).keyID("rsa-key").generate();
        var token = tokenSignedWith(JWSAlgorithm.RS256, rsa, new RSASSASigner(rsa));

        // Act + Assert
        expectRejectedFor(token, "algorithm_or_kid");
        verify(jwksClient, never()).keys();
    }

    @Test
    void verify_es384WithAP384KeyOfTheVerifier_isInvalidToken() throws Exception {
        // Arrange
        var p384 = new ECKeyGenerator(Curve.P_384).keyID("p384-key").generate();

        // Act + Assert
        expectRejectedFor(tokenSignedWith(JWSAlgorithm.ES384, p384, new ECDSASigner(p384)), "algorithm_or_kid");
    }

    @Test
    void verify_es256HeaderNamingAnRsaKey_isInvalidToken() throws Exception {
        // Arrange: the kid names an RSA key of the set, the header says ES256
        var rsa = new RSAKeyGenerator(2048).keyID("rsa-key").generate();
        var ec = new ECKeyGenerator(Curve.P_256).keyID("rsa-key").generate();
        var token = tokenSignedWith(JWSAlgorithm.ES256, rsa, new ECDSASigner(ec));

        // Act + Assert
        expectRejectedFor(token, "key_type");
    }

    @Test
    void verify_notBeforeLaterThanTheClockSkew_isInvalidToken() {
        var token = verifierKeys.token(ISSUER, TENANT,
                claims -> claims.notBeforeTime(Date.from(Instant.now().plus(SystemTokenVerifier.CLOCK_SKEW).plusSeconds(30))));

        expectRejectedFor(token, "not_yet_valid");
    }

    @Test
    void verify_issuedLaterThanTheClockSkew_isInvalidToken() {
        var token = verifierKeys.token(ISSUER, TENANT,
                claims -> claims.issueTime(Date.from(Instant.now().plus(SystemTokenVerifier.CLOCK_SKEW).plusSeconds(30))));

        expectRejectedFor(token, "issued_in_the_future");
    }

    @Test
    void verify_notBeforeAndIssueTimeWithinTheClockSkew_isAccepted() {
        // Arrange: the clock of the Verifier 30 s ahead of this service
        var ahead = Date.from(Instant.now().plusSeconds(30));
        var token = verifierKeys.token(ISSUER, TENANT, claims -> claims.notBeforeTime(ahead).issueTime(ahead));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }

    @Test
    void verify_withoutNotBeforeNorIssueTime_isAccepted() {
        // Arrange: both optional, as in the Issuer
        var token = verifierKeys.token(ISSUER, TENANT, claims -> claims.notBeforeTime(null).issueTime(null));

        // Act + Assert
        StepVerifier.create(tokenVerifier.verify(token, TENANT, ISSUER)).expectNextCount(1).verifyComplete();
    }
}
