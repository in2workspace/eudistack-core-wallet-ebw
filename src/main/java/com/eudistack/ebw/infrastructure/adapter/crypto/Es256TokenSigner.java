package com.eudistack.ebw.infrastructure.adapter.crypto;

import com.eudistack.ebw.domain.model.exception.InvalidTokenException;
import com.eudistack.ebw.domain.spi.TokenSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class Es256TokenSigner implements TokenSigner {

    private static final Logger log = LoggerFactory.getLogger(Es256TokenSigner.class);

    private final String privateKeyPath;
    private JWSSigner signer;
    private JWSVerifier verifier;

    public Es256TokenSigner(com.eudistack.ebw.infrastructure.adapter.properties.JwtProperties jwtProperties) {
        this.privateKeyPath = jwtProperties.privateKeyPath();
    }

    @PostConstruct
    void init() {
        if (privateKeyPath == null || privateKeyPath.isBlank()) {
            log.warn("JWT private key path not configured — token signing will fail at runtime");
            return;
        }
        try {
            var pem = Files.readString(Path.of(privateKeyPath));
            var jwk = JWK.parseFromPEMEncodedObjects(pem);
            var ecKey = jwk.toECKey();

            this.signer = new ECDSASigner(ecKey);
            this.verifier = new ECDSAVerifier(ecKey.toPublicJWK());
            log.info("JWT ES256 key loaded successfully");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load JWT private key from " + privateKeyPath, e);
        }
    }

    @Override
    public String sign(Map<String, Object> claims) {
        if (signer == null) {
            throw new IllegalStateException("JWT signer not initialized — check private key configuration");
        }
        try {
            var builder = new JWTClaimsSet.Builder();
            claims.forEach((key, value) -> {
                switch (key) {
                    case "exp", "iat" -> builder.claim(key, new Date(((Number) value).longValue() * 1000));
                    default -> builder.claim(key, value);
                }
            });

            var header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
            var signedJWT = new SignedJWT(header, builder.build());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    @Override
    public Map<String, Object> verify(String token) {
        if (verifier == null) {
            throw new IllegalStateException("JWT verifier not initialized — check private key configuration");
        }
        try {
            var signedJWT = SignedJWT.parse(token);

            if (!JWSAlgorithm.ES256.equals(signedJWT.getHeader().getAlgorithm())) {
                throw new InvalidTokenException("Unsupported JWT algorithm");
            }

            if (!signedJWT.verify(verifier)) {
                throw new InvalidTokenException("Invalid JWT signature");
            }

            var claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet.getExpirationTime() != null &&
                    claimsSet.getExpirationTime().toInstant().isBefore(Instant.now())) {
                throw new InvalidTokenException("JWT has expired");
            }

            var result = new HashMap<String, Object>();
            result.put("sub", claimsSet.getSubject());
            result.put("email", claimsSet.getStringClaim("email"));
            result.put("iss", claimsSet.getIssuer());
            result.put("iat", claimsSet.getIssueTime());
            result.put("exp", claimsSet.getExpirationTime());
            // Pass through PBAC powers and OAuth2-style scope claims if present so the
            // security filter can map them to granted authorities. Additive — no behaviour
            // change for existing tokens that carry neither claim.
            var powers = claimsSet.getClaim("powers");
            if (powers != null) {
                result.put("powers", powers);
            }
            var scope = claimsSet.getClaim("scope");
            if (scope != null) {
                result.put("scope", scope);
            }
            var scp = claimsSet.getClaim("scp");
            if (scp != null) {
                result.put("scp", scp);
            }
            return result;
        } catch (InvalidTokenException e) {
            throw e;
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Malformed JWT");
        }
    }
}
