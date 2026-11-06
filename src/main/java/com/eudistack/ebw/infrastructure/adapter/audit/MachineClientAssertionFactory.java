package com.eudistack.ebw.infrastructure.adapter.audit;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Builds the {@code client_assertion} with which a service authenticates against the Verifier as a machine
 * (EUD-299): a JWT signed with the key bound to its machine attestation, carrying in {@code vp_token} a
 * presentation of that attestation signed with the same key. The Verifier checks {@code iss} = {@code sub} =
 * client id, {@code aud} = its own URL, a {@code jti} it has not seen, and the expiry.
 */
final class MachineClientAssertionFactory {

    private static final Duration PRESENTATION_LIFETIME = Duration.ofMinutes(5);
    private static final Duration ASSERTION_LIFETIME = Duration.ofMinutes(2);

    private final String clientId;
    private final String attestation;
    private final String assertionAudience;
    private final ECKey signingKey;
    private final Clock clock;

    MachineClientAssertionFactory(String clientId, String attestation, String privateKeyJwk,
                                  String assertionAudience, Clock clock) {
        this.clientId = requireText(clientId, "AUDIT_M2M_CLIENT_ID");
        this.attestation = requireText(attestation, "AUDIT_M2M_CREDENTIAL");
        this.assertionAudience = requireText(assertionAudience, "AUDIT_M2M_ASSERTION_AUDIENCE");
        this.signingKey = parseKey(requireText(privateKeyJwk, "AUDIT_M2M_PRIVATE_KEY"));
        this.clock = clock;
    }

    /** A new assertion on every call: the Verifier rejects a {@code jti} it has already seen. */
    String build() {
        try {
            String presentation = sign(presentationClaims(clock.instant()));
            String vpToken = Base64.getEncoder().encodeToString(presentation.getBytes(StandardCharsets.US_ASCII));
            return sign(assertionClaims(clock.instant(), vpToken));
        } catch (JOSEException e) {
            throw new IllegalStateException("The audit machine assertion could not be signed", e);
        }
    }

    private JWTClaimsSet presentationClaims(Instant now) {
        Map<String, Object> presentation = Map.of(
                "@context", List.of("https://www.w3.org/2018/credentials/v1"),
                "type", List.of("VerifiablePresentation"),
                "verifiableCredential", List.of(attestation));
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(PRESENTATION_LIFETIME)))
                .jwtID(UUID.randomUUID().toString())
                .claim("vp", presentation)
                .build();
    }

    private JWTClaimsSet assertionClaims(Instant now, String vpToken) {
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(assertionAudience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ASSERTION_LIFETIME)))
                .jwtID(UUID.randomUUID().toString())
                .claim("vp_token", vpToken)
                .build();
    }

    /** The public key travels in the JOSE header: it is the proof of possession the Verifier checks. */
    private String sign(JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .jwk(new ECKey.Builder(signingKey.getCurve(), signingKey.getX(), signingKey.getY()).build())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    private static ECKey parseKey(String privateKeyJwk) {
        try {
            ECKey key = ECKey.parse(privateKeyJwk);
            if (!key.isPrivate()) {
                throw new IllegalArgumentException("AUDIT_M2M_PRIVATE_KEY must be a private EC key");
            }
            return key;
        } catch (ParseException e) {
            throw new IllegalArgumentException("AUDIT_M2M_PRIVATE_KEY is not a valid EC JWK", e);
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is not set");
        }
        return value.trim();
    }
}
