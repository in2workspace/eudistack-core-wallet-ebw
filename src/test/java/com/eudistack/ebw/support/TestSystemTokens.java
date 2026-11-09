package com.eudistack.ebw.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A fake tenant Verifier: an EC key and system tokens laid out as the Verifier's
 * {@code JwsAccessTokenBuilder} writes them for a LEARCredentialMachine (client_credentials).
 */
public final class TestSystemTokens {

    private final ECKey key;

    public TestSystemTokens() {
        this("verifier-key-" + UUID.randomUUID());
    }

    public TestSystemTokens(String kid) {
        try {
            key = new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public JWKSet publicJwks() {
        return new JWKSet(key.toPublicJWK());
    }

    public String kid() {
        return key.getKeyID();
    }

    /** Tenant administrator power of {@code domain} (AD-9): organization · domain · Onboarding · Execute. */
    public static Map<String, Object> onboardingPower(String domain) {
        return Map.of("type", "organization", "domain", domain, "function", "Onboarding",
                "action", List.of("Execute"));
    }

    /** Valid system token of a tenant administrator machine. */
    public String token(String issuer, String tenant) {
        return token(issuer, tenant, "LEARCredentialMachine", List.of(onboardingPower(tenant)),
                Instant.now().plus(Duration.ofMinutes(5)));
    }

    public String token(String issuer, String tenant, String credentialType, List<Map<String, Object>> powers,
                        Instant expiresAt) {
        var claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(issuer)
                .subject("portal-machine.example.org")
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(expiresAt))
                .claim("scope", "machine learcredential")
                .claim("credential_type", credentialType)
                .claim("tenant", tenant)
                .claim("power", powers)
                .claim("mandatee", Map.of("domain", "portal-machine.example.org"))
                .build();
        try {
            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
