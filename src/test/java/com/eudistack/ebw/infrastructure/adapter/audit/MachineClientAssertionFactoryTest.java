package com.eudistack.ebw.infrastructure.adapter.audit;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MachineClientAssertionFactoryTest {

    private static final String CLIENT_ID = "did:key:zMachine";
    private static final String ATTESTATION = "header.payload.signature";
    private static final String VERIFIER_URL = "https://dome.dev.eudistack.net/verifier";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-06T10:00:00Z"), ZoneOffset.UTC);

    private ECKey key;
    private MachineClientAssertionFactory factory;

    @BeforeEach
    void setUp() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).generate();
        factory = new MachineClientAssertionFactory(CLIENT_ID, ATTESTATION, key.toJSONString(), VERIFIER_URL, CLOCK);
    }

    @Test
    void build_returnsAnAssertionSignedByTheMachineKeyWithTheClaimsTheVerifierChecks() throws Exception {
        // Act
        SignedJWT assertion = SignedJWT.parse(factory.build());

        // Assert
        assertTrue(assertion.verify(new ECDSAVerifier(key.toPublicJWK())));
        assertEquals(CLIENT_ID, assertion.getJWTClaimsSet().getIssuer());
        assertEquals(CLIENT_ID, assertion.getJWTClaimsSet().getSubject());
        assertEquals(List.of(VERIFIER_URL), assertion.getJWTClaimsSet().getAudience());
        assertEquals(CLOCK.instant().plusSeconds(120), assertion.getJWTClaimsSet().getExpirationTime().toInstant());
    }

    @Test
    void build_carriesTheAttestationInAPresentationSignedByTheSameKeyWithItsPublicKeyInTheHeader() throws Exception {
        // Arrange
        SignedJWT assertion = SignedJWT.parse(factory.build());
        String vpToken = assertion.getJWTClaimsSet().getStringClaim("vp_token");

        // Act
        SignedJWT presentation = SignedJWT.parse(
                new String(Base64.getDecoder().decode(vpToken), StandardCharsets.US_ASCII));

        // Assert
        assertTrue(presentation.verify(new ECDSAVerifier(key.toPublicJWK())));
        assertEquals(key.toPublicJWK().getX(), ((ECKey) presentation.getHeader().getJWK()).getX());
        assertFalse(presentation.getHeader().getJWK().isPrivate());
        Map<String, Object> vp = presentation.getJWTClaimsSet().getJSONObjectClaim("vp");
        assertEquals(List.of(ATTESTATION), vp.get("verifiableCredential"));
    }

    @Test
    void build_usesANewJtiEveryTimeBecauseTheVerifierRejectsAReplay() throws Exception {
        // Act
        String first = SignedJWT.parse(factory.build()).getJWTClaimsSet().getJWTID();
        String second = SignedJWT.parse(factory.build()).getJWTClaimsSet().getJWTID();

        // Assert
        assertNotEquals(first, second);
    }

    @Test
    void constructor_privateKeyMissing_failsNamingTheVariable() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new MachineClientAssertionFactory(CLIENT_ID, ATTESTATION, " ", VERIFIER_URL, CLOCK));

        assertEquals("AUDIT_M2M_PRIVATE_KEY is not set", error.getMessage());
    }

    @Test
    void constructor_keyWithoutItsPrivatePart_isRejected() {
        String publicOnly = key.toPublicJWK().toJSONString();

        assertThrows(IllegalArgumentException.class,
                () -> new MachineClientAssertionFactory(CLIENT_ID, ATTESTATION, publicOnly, VERIFIER_URL, CLOCK));
    }

    @Test
    void constructor_keyThatIsNotAJwk_isRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new MachineClientAssertionFactory(CLIENT_ID, ATTESTATION, "not-a-jwk", VERIFIER_URL, CLOCK));
    }

    @Test
    void parseCheck_theTestKeyIsParseable() throws ParseException {
        assertEquals(key.getX(), ECKey.parse(key.toJSONString()).getX());
    }
}
