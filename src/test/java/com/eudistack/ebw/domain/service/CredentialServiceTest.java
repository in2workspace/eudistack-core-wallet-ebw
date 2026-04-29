package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.CredentialFormat;
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

import java.util.Date;
import java.util.List;
import java.util.Map;

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
