package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse.IssuerDto;
import com.eudistack.ebw.domain.model.exception.MalformedCredentialException;
import com.eudistack.ebw.domain.model.exception.UnsupportedFormatException;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CredentialServiceTest {

    private static final byte[] HMAC_KEY = "test-hmac-key-for-credential-jwt".getBytes();

    private CredentialService credentialService;
    private HashProvider hashProvider;

    @BeforeEach
    void setUp() {
        hashProvider = mock(HashProvider.class);
        when(hashProvider.sha256(anyString())).thenReturn("mocked-hash");
        credentialService = new CredentialService(hashProvider, new ObjectMapper());
    }

    @Test
    void parseJwtCredential_extractsMetadata() {
        var jwt = buildJwt("https://issuer.com", "did:example:sub",
                List.of("VerifiableCredential", "LEARCredentialEmployee"), null);

        StepVerifier.create(credentialService.parseCredential(jwt, CredentialFormat.JWT_VC_JSON))
                .assertNext(parsed -> {
                    assertThat(parsed.issuer()).isEqualTo("https://issuer.com");
                    assertThat(parsed.subject()).isEqualTo("did:example:sub");
                    assertThat(parsed.credentialType()).isEqualTo("LEARCredentialEmployee");
                    assertThat(parsed.issuanceDate()).isNotNull();
                    assertThat(parsed.vct()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void parseSdJwtCredential_extractsVct() {
        var jwt = buildJwt("https://issuer.com", "did:example:sub", null, "urn:credential:lear");
        var sdJwt = jwt + "~disclosure1~disclosure2~";

        StepVerifier.create(credentialService.parseCredential(sdJwt, CredentialFormat.DC_SD_JWT))
                .assertNext(parsed -> {
                    assertThat(parsed.issuer()).isEqualTo("https://issuer.com");
                    assertThat(parsed.vct()).isEqualTo("urn:credential:lear");
                })
                .verifyComplete();
    }

    @Test
    void parseMalformedJwt_throwsMalformedCredentialException() {
        StepVerifier.create(credentialService.parseCredential("not.a.jwt", CredentialFormat.JWT_VC_JSON))
                .expectError(MalformedCredentialException.class)
                .verify();
    }

    @Test
    void validateFormat_validFormats() {
        assertThat(credentialService.validateFormat("jwt_vc_json")).isEqualTo(CredentialFormat.JWT_VC_JSON);
        assertThat(credentialService.validateFormat("dc+sd-jwt")).isEqualTo(CredentialFormat.DC_SD_JWT);
    }

    @Test
    void validateFormat_unsupported_throws() {
        assertThatThrownBy(() -> credentialService.validateFormat("unknown"))
                .isInstanceOf(UnsupportedFormatException.class);
    }

    @Test
    void computeAuditHash_delegatesToHashProvider() {
        var result = credentialService.computeAuditHash("some-credential");
        assertThat(result).isEqualTo("mocked-hash");
    }

    // --- parseCredential: claim extraction edge cases ---

    @Test
    void parseCredential_jwtWithW3cIssuerObjectAndNoTimes_usesIssuerIdAndNow() {
        // Arrange
        var before = Instant.now();
        var jwt = signedJwt(new JWTClaimsSet.Builder()
                .claim("issuer", Map.of("id", "did:elsi:VATES-A1", "organization", "Org"))
                .claim("type", List.of("VerifiableCredential", "LEARCredentialMachine"))
                .build());

        // Act
        var result = credentialService.parseCredential(jwt, CredentialFormat.JWT_VC_JSON);

        // Assert
        StepVerifier.create(result)
                .assertNext(parsed -> {
                    assertThat(parsed.issuer()).isEqualTo("did:elsi:VATES-A1");
                    assertThat(parsed.credentialType()).isEqualTo("LEARCredentialMachine");
                    assertThat(parsed.issuanceDate()).isAfterOrEqualTo(before);
                    assertThat(parsed.expirationDate()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void parseCredential_typeClaimIsAString_returnsItAsIs() {
        // Arrange
        var jwt = signedJwt(new JWTClaimsSet.Builder().issuer("iss").claim("type", "SingleType").build());

        // Act
        var result = credentialService.parseCredential(jwt, CredentialFormat.JWT_VC_JSON);

        // Assert
        StepVerifier.create(result)
                .assertNext(parsed -> assertThat(parsed.credentialType()).isEqualTo("SingleType"))
                .verifyComplete();
    }

    @Test
    void parseCredential_noTypeInformation_returnsUnknown() {
        // Arrange
        var jwt = signedJwt(new JWTClaimsSet.Builder().issuer("iss")
                .claim("vc", Map.of("type", List.of()))
                .build());

        // Act
        var result = credentialService.parseCredential(jwt, CredentialFormat.JWT_VC_JSON);

        // Assert
        StepVerifier.create(result)
                .assertNext(parsed -> assertThat(parsed.credentialType()).isEqualTo("Unknown"))
                .verifyComplete();
    }

    @Test
    void parseCredential_jwtWithVctClaim_usesVctAsCredentialType() {
        // Arrange
        var jwt = signedJwt(new JWTClaimsSet.Builder().issuer("iss").claim("vct", "urn:vct:pid").build());

        // Act
        var result = credentialService.parseCredential(jwt, CredentialFormat.JWT_VC_JSON);

        // Assert
        StepVerifier.create(result)
                .assertNext(parsed -> assertThat(parsed.credentialType()).isEqualTo("urn:vct:pid"))
                .verifyComplete();
    }

    @Test
    void parseCredential_sdJwtWithoutIssuerSignedJwt_throwsMalformedCredentialException() {
        // Act
        var result = credentialService.parseCredential("~disclosure~", CredentialFormat.DC_SD_JWT);

        // Assert
        StepVerifier.create(result)
                .expectError(MalformedCredentialException.class)
                .verify();
    }

    @Test
    void parseCredential_sdJwtWithoutTimes_defaultsIssuanceToNow() {
        // Arrange
        var sdJwt = signedJwt(new JWTClaimsSet.Builder().issuer("iss").build()) + "~";

        // Act
        var result = credentialService.parseCredential(sdJwt, CredentialFormat.DC_SD_JWT);

        // Assert
        StepVerifier.create(result)
                .assertNext(parsed -> {
                    assertThat(parsed.issuanceDate()).isNotNull();
                    assertThat(parsed.expirationDate()).isNull();
                    assertThat(parsed.vct()).isNull();
                    assertThat(parsed.credentialType()).isEqualTo("Unknown");
                })
                .verifyComplete();
    }

    // --- toVerifiableCredential ---

    @Test
    void toVerifiableCredential_rawIsNull_returnsFallbackFromStoredColumns() {
        // Arrange
        var issuance = Instant.parse("2026-01-01T00:00:00Z");
        var expiration = Instant.parse("2027-01-01T00:00:00Z");
        var credential = credential(null, CredentialFormat.JWT_VC_JSON, issuance, expiration);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.id()).isEqualTo(credential.getId().toString());
        assertThat(vc.type()).containsExactly("VerifiableCredential");
        assertThat(vc.issuer().id()).isEqualTo("https://stored-issuer");
        assertThat(vc.validFrom()).isEqualTo("2026-01-01T00:00:00Z");
        assertThat(vc.validUntil()).isEqualTo("2027-01-01T00:00:00Z");
        assertThat(vc.credentialEncoded()).isNull();
        assertThat(vc.credentialFormat()).isEqualTo("jwt_vc_json");
        assertThat(vc.kid()).isEqualTo("kid-1");
        assertThat(vc.holderKeyId()).isEqualTo("holder-key-1");
        assertThat(vc.lifeCycleStatus()).isEqualTo("VALID");
    }

    @Test
    void toVerifiableCredential_unparseableRaw_returnsFallbackWithoutDates() {
        // Arrange
        var credential = credential("not-a-jwt", CredentialFormat.JWT_VC_JSON, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.credentialSubject()).isEqualTo(Map.of());
        assertThat(vc.validFrom()).isNull();
        assertThat(vc.validUntil()).isNull();
        assertThat(vc.credentialStatus().id()).isEmpty();
    }

    @Test
    void toVerifiableCredential_sdJwtWithBlankIssuerJwt_returnsFallback() {
        // Arrange
        var credential = credential("~disclosure", CredentialFormat.DC_SD_JWT, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.type()).containsExactly("VerifiableCredential");
        assertThat(vc.credentialEncoded()).isNull();
        assertThat(vc.credentialFormat()).isEqualTo("dc+sd-jwt");
    }

    @Test
    void toVerifiableCredential_sdJwtWithDisclosures_buildsSubjectFromNonStandardDisclosures() {
        // Arrange
        var issuerJwt = signedJwt(new JWTClaimsSet.Builder()
                .issuer("https://issuer.example")
                .issueTime(Date.from(Instant.parse("2026-02-01T10:00:00Z")))
                .expirationTime(Date.from(Instant.parse("2027-02-01T10:00:00Z")))
                .claim("status", Map.of("status_list", Map.of("idx", 42, "uri", "https://status/1")))
                .build());
        var twoItemDisclosure = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("[\"salt\",\"value\"]".getBytes(StandardCharsets.UTF_8));
        var raw = issuerJwt
                + "~" + disclosure("salt1", "given_name", "Alice")
                + "~" + disclosure("salt2", "vct", "urn:vct:employee")
                + "~" + "!!not-base64!!"
                + "~" + twoItemDisclosure
                + "~~" + "aaa.bbb.ccc";
        var credential = credential(raw, CredentialFormat.DC_SD_JWT, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.type()).containsExactly("VerifiableCredential", "urn:vct:employee");
        assertThat(vc.context()).containsExactly("https://www.w3.org/2018/credentials/v1");
        assertThat(vc.issuer().id()).isEqualTo("https://issuer.example");
        assertThat(vc.validFrom()).isEqualTo("2026-02-01T10:00:00Z");
        assertThat(vc.validUntil()).isEqualTo("2027-02-01T10:00:00Z");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of("given_name", "Alice"));
        assertThat(vc.credentialStatus().statusListIndex()).isEqualTo("42");
        assertThat(vc.credentialStatus().statusListCredential()).isEqualTo("https://status/1");
        assertThat(vc.credentialStatus().type()).isEqualTo("StatusList2021Entry");
        assertThat(vc.credentialEncoded()).isEqualTo(raw);
    }

    @Test
    void toVerifiableCredential_sdJwtWithExplicitClaims_prefersThemOverDefaults() {
        // Arrange
        var issuerJwt = signedJwt(new JWTClaimsSet.Builder()
                .claim("@context", List.of("https://ctx/1"))
                .claim("type", List.of("VerifiableCredential", "Explicit"))
                .claim("issuer", Map.of("id", "did:issuer", "organization", "Org", "country", "ES",
                        "organizationIdentifier", "VATES-1", "commonName", "CN", "serialNumber", "SN"))
                .claim("validFrom", "2026-03-01T00:00:00Z")
                .claim("validUntil", "2027-03-01T00:00:00Z")
                .claim("credentialSubject", Map.of("mandate", Map.of("id", "m-1")))
                .claim("credentialStatus", Map.of("id", "cs-1", "type", "BitstringStatusListEntry",
                        "statusPurpose", "revocation", "statusListIndex", "7",
                        "statusListCredential", "https://status/list"))
                .claim("name", "Credential name")
                .claim("description", "Credential description")
                .build());
        var credential = credential(issuerJwt + "~" + disclosure("s", "extra", "ignored"),
                CredentialFormat.DC_SD_JWT, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.context()).containsExactly("https://ctx/1");
        assertThat(vc.type()).containsExactly("VerifiableCredential", "Explicit");
        assertThat(vc.issuer()).isEqualTo(new IssuerDto("did:issuer", "Org", "VATES-1", "ES", "CN", "SN"));
        assertThat(vc.validFrom()).isEqualTo("2026-03-01T00:00:00Z");
        assertThat(vc.validUntil()).isEqualTo("2027-03-01T00:00:00Z");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of("mandate", Map.of("id", "m-1")));
        assertThat(vc.credentialStatus().id()).isEqualTo("cs-1");
        assertThat(vc.credentialStatus().statusListIndex()).isEqualTo("7");
        assertThat(vc.name()).isEqualTo("Credential name");
        assertThat(vc.description()).isEqualTo("Credential description");
    }

    @Test
    void toVerifiableCredential_sdJwtWithOnlyStandardDisclosures_returnsEmptySubject() {
        // Arrange
        var issuerJwt = signedJwt(new JWTClaimsSet.Builder()
                .claim("vct", "urn:vct:top")
                .claim("status", Map.of("other", "value"))
                .build());
        var raw = issuerJwt + "~" + disclosure("s", "iat", 1700000000) + "~";
        var credential = credential(raw, CredentialFormat.DC_SD_JWT, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.type()).containsExactly("VerifiableCredential", "urn:vct:top");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of());
        assertThat(vc.issuer().id()).isEqualTo("unknown");
        assertThat(vc.validFrom()).isNull();
        assertThat(vc.validUntil()).isNull();
        assertThat(vc.credentialStatus().id()).isEmpty();
    }

    @Test
    void toVerifiableCredential_sdJwtWithoutDisclosuresOrType_returnsBaseType() {
        // Arrange
        var raw = signedJwt(new JWTClaimsSet.Builder().issuer("iss").build());
        var credential = credential(raw, CredentialFormat.DC_SD_JWT, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.type()).containsExactly("VerifiableCredential");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of());
    }

    @Test
    void toVerifiableCredential_jwtVcWithNestedVcClaims_readsThemFromVc() {
        // Arrange
        var raw = signedJwt(new JWTClaimsSet.Builder()
                .claim("issuer", "did:issuer:string")
                .claim("issuanceDate", "2026-04-01T00:00:00Z")
                .claim("expirationDate", "2027-04-01T00:00:00Z")
                .claim("vc", Map.of(
                        "@context", List.of("https://www.w3.org/ns/credentials/v2"),
                        "type", List.of("VerifiableCredential", "LEARCredentialEmployee"),
                        "credentialSubject", Map.of("id", "did:subject"),
                        "credentialStatus", Map.of("id", "cs-2"),
                        "name", "LEAR",
                        "description", "Employee mandate"))
                .build());
        var credential = credential(raw, CredentialFormat.JWT_VC_JSON, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.context()).containsExactly("https://www.w3.org/ns/credentials/v2");
        assertThat(vc.type()).containsExactly("VerifiableCredential", "LEARCredentialEmployee");
        assertThat(vc.issuer().id()).isEqualTo("did:issuer:string");
        assertThat(vc.validFrom()).isEqualTo("2026-04-01T00:00:00Z");
        assertThat(vc.validUntil()).isEqualTo("2027-04-01T00:00:00Z");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of("id", "did:subject"));
        assertThat(vc.credentialStatus().id()).isEqualTo("cs-2");
        assertThat(vc.credentialStatus().type()).isNull();
        assertThat(vc.name()).isEqualTo("LEAR");
        assertThat(vc.description()).isEqualTo("Employee mandate");
    }

    @Test
    void toVerifiableCredential_jwtVcWithoutVcClaim_usesTopLevelClaims() {
        // Arrange
        var raw = signedJwt(new JWTClaimsSet.Builder()
                .issuer("https://iss")
                .issueTime(Date.from(Instant.parse("2026-05-01T00:00:00Z")))
                .expirationTime(Date.from(Instant.parse("2027-05-01T00:00:00Z")))
                .build());
        var credential = credential(raw, CredentialFormat.JWT_VC_JSON, null, null);

        // Act
        var vc = credentialService.toVerifiableCredential(credential);

        // Assert
        assertThat(vc.type()).containsExactly("VerifiableCredential");
        assertThat(vc.issuer().id()).isEqualTo("https://iss");
        assertThat(vc.validFrom()).isEqualTo("2026-05-01T00:00:00Z");
        assertThat(vc.validUntil()).isEqualTo("2027-05-01T00:00:00Z");
        assertThat(vc.credentialSubject()).isEqualTo(Map.of());
        assertThat(vc.name()).isNull();
    }

    // --- validateStatusTransition ---

    @Test
    void validateStatusTransition_revokedToValid_throwsInvalidTransitionException() {
        // Act + Assert
        assertThatThrownBy(() -> credentialService.validateStatusTransition(
                CredentialStatus.REVOKED, CredentialStatus.VALID))
                .isInstanceOf(InvalidTransitionException.class);
    }

    private WalletCredential credential(String raw, CredentialFormat format, Instant issuance, Instant expiration) {
        return new WalletCredential(UUID.randomUUID(), UUID.randomUUID(), raw, format, "config-1", "kid-1",
                "Type", null, "https://stored-issuer", "subject", issuance, expiration,
                CredentialStatus.VALID, Map.of(), "holder-key-1", Instant.now(), Instant.now());
    }

    private static String disclosure(String salt, String name, Object value) {
        try {
            var json = new ObjectMapper().writeValueAsBytes(List.of(salt, name, value));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String signedJwt(JWTClaimsSet claims) {
        try {
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            jwt.sign(new MACSigner(HMAC_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String buildJwt(String issuer, String subject, List<String> types, String vct) {
        try {
            var builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 86400_000));

            if (types != null) {
                builder.claim("vc", Map.of("type", types));
            }
            if (vct != null) {
                builder.claim("vct", vct);
            }

            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), builder.build());
            jwt.sign(new MACSigner(HMAC_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
