package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.infrastructure.adapter.verifier.VerifierJwksClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Validates the system token of {@code POST /onboarding-tickets} (design §2.6, AD-9): an access
 * token issued by the tenant's Verifier to a system authenticated with its LEARCredentialMachine
 * (client_credentials). Checks, in this order: {@code iss}, signature with the Verifier JWK Set
 * (one reload for an unknown {@code kid}), {@code exp}, {@code nbf} and {@code iat}, {@code tenant},
 * {@code credential_type} and the tenant administrator power.
 *
 * <p>Only ES256 with an EC key (SEC-04): the Verifier signs its access tokens with ES256 and a P-256
 * key ({@code AuthorizationServerConfig.jwtCustomizer}, {@code CryptoComponent}). A {@code nbf} or
 * {@code iat} later than now plus {@link #CLOCK_SKEW} is rejected; both are optional, as in the
 * Issuer's {@code VerifierServiceImpl}, which does not check them and has no tolerance of its own
 * (security audit F3-n).
 *
 * <p>Claims as the Verifier writes them ({@code JwsAccessTokenBuilder}): {@code tenant} is the
 * tenant of the client registration, which may carry an environment suffix ({@code -stg});
 * {@code credential_type} is the credential {@code type} other than {@code VerifiableCredential}
 * ({@code LEARCredentialMachine}) for a W3C credential, or its configuration id
 * ({@code learcredential.machine.*}) for an SD-JWT one; {@code power} is the top-level copy of
 * the mandate's powers, whose fields may come as their {@code tmf_} aliases; and {@code sub}
 * identifies the machine (mandatee). The tokens carry no {@code client_id}: {@code sub}
 * identifies the system. The claims are read as the Issuer reads them ({@code JwtCallerProvider},
 * {@code PowerAuthorizationServiceImpl}, {@code TenantIdentifiers}) (EC-14).
 */
@Slf4j
@Component
public class SystemTokenVerifier {

    static final String MACHINE_CREDENTIAL_TYPE = "LEARCredentialMachine";
    static final String MACHINE_CONFIGURATION_PREFIX = "learcredential.machine.";
    static final String ORGANIZATION_POWER_TYPE = "organization";
    static final String ONBOARDING_FUNCTION = "Onboarding";
    static final String EXECUTE_ACTION = "Execute";
    private static final List<String> ENV_SUFFIXES = List.of("-stg", "-dev", "-pre");
    private static final List<String> POWER_FIELDS = List.of("action", "domain", "function", "type");
    private static final String ALIAS_PREFIX = "tmf_";
    private static final int MAX_CALLER_LENGTH = 255;
    private static final JWSAlgorithm ACCEPTED_ALGORITHM = JWSAlgorithm.ES256;
    /** Tolerance for the clocks of the Verifier and this service on {@code nbf} and {@code iat}. */
    static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private final VerifierJwksClient jwksClient;
    private final Clock clock;

    /** The constructor Spring uses: with two constructors it needs to be told which one. */
    @Autowired
    public SystemTokenVerifier(VerifierJwksClient jwksClient) {
        this(jwksClient, Clock.systemUTC());
    }

    SystemTokenVerifier(VerifierJwksClient jwksClient, Clock clock) {
        this.jwksClient = jwksClient;
        this.clock = clock;
    }

    /**
     * @param expectedIssuer the tenant's Verifier as seen by the request
     * @return the calling system; error {@link SystemTokenRejectedException} when the token is not
     *         accepted, or {@link com.eudistack.ebw.infrastructure.adapter.verifier.VerifierUnavailableException}
     *         when the Verifier keys cannot be read
     */
    public Mono<SystemCaller> verify(String rawToken, String tenant, String expectedIssuer) {
        return Mono.defer(() -> {
            var token = parse(rawToken);
            var claims = claims(token);
            if (!sameIssuer(claims.getIssuer(), expectedIssuer)) {
                return reject(SystemTokenRejectedException.invalidToken("issuer"));
            }
            if (!ACCEPTED_ALGORITHM.equals(token.getHeader().getAlgorithm())
                    || token.getHeader().getKeyID() == null) {
                return reject(SystemTokenRejectedException.invalidToken("algorithm_or_kid"));
            }
            return keyOf(token)
                    .flatMap(key -> {
                        verifySignature(token, key);
                        return Mono.just(authorize(claims, tenant));
                    });
        });
    }

    private Mono<JWK> keyOf(SignedJWT token) {
        var kid = token.getHeader().getKeyID();
        return jwksClient.keys()
                .flatMap(keys -> Mono.justOrEmpty(keys.getKeyByKeyId(kid)))
                // ES-04: a key the cached set does not know may be a rotated one.
                .switchIfEmpty(Mono.defer(() -> jwksClient.reload().mapNotNull(keys -> keys.getKeyByKeyId(kid))))
                .switchIfEmpty(Mono.defer(() -> reject(SystemTokenRejectedException.invalidToken("unknown_kid"))));
    }

    private SystemCaller authorize(JWTClaimsSet claims, String tenant) {
        var now = clock.instant();
        var expiration = claims.getExpirationTime();
        if (expiration == null || !expiration.toInstant().isAfter(now)) {
            throw SystemTokenRejectedException.invalidToken("expired");
        }
        var notBefore = claims.getNotBeforeTime();
        if (notBefore != null && isInTheFuture(notBefore.toInstant(), now)) {
            throw SystemTokenRejectedException.invalidToken("not_yet_valid");
        }
        var issuedAt = claims.getIssueTime();
        if (issuedAt != null && isInTheFuture(issuedAt.toInstant(), now)) {
            throw SystemTokenRejectedException.invalidToken("issued_in_the_future");
        }
        var expectedTenant = stripEnvSuffix(tenant);
        if (expectedTenant == null || !(claims.getClaim("tenant") instanceof String tokenTenant)
                || !expectedTenant.equalsIgnoreCase(stripEnvSuffix(tokenTenant))) {
            throw SystemTokenRejectedException.invalidToken("tenant");
        }
        if (!isMachineCredential(claims.getClaim("credential_type"))) {
            throw SystemTokenRejectedException.insufficientPermission("credential_type");
        }
        if (!hasTenantAdministratorPower(claims.getClaim("power"), expectedTenant)) {
            throw SystemTokenRejectedException.insufficientPermission("power");
        }
        return new SystemCaller(callerOf(claims));
    }

    private static boolean isInTheFuture(Instant time, Instant now) {
        return time.isAfter(now.plus(CLOCK_SKEW));
    }

    /**
     * A LEAR machine attestation, by its W3C type or its SD-JWT configuration id, as the Issuer's
     * {@code PowerAuthorizationServiceImpl.isSystem}.
     */
    static boolean isMachineCredential(Object credentialType) {
        if (!(credentialType instanceof String type)) {
            return false;
        }
        var normalized = type.toLowerCase(Locale.ROOT);
        return normalized.equals(MACHINE_CREDENTIAL_TYPE.toLowerCase(Locale.ROOT))
                || normalized.startsWith(MACHINE_CONFIGURATION_PREFIX);
    }

    /** The tenant without its environment suffix, as the Issuer's {@code TenantIdentifiers.stripEnvSuffix}. */
    static String stripEnvSuffix(String tenant) {
        if (tenant == null) {
            return null;
        }
        for (var suffix : ENV_SUFFIXES) {
            if (tenant.endsWith(suffix)) {
                return tenant.substring(0, tenant.length() - suffix.length());
            }
        }
        return tenant;
    }

    /**
     * Tenant administrator (design AD-9): a power {@code organization} · tenant · {@code Onboarding}
     * · {@code Execute}, the {@code tenant_admin} user type of the Issuer's authorization matrix
     * ({@code authorization-matrix.yaml}, {@code AuthorizationMatrix.PowerPattern.isHeldBy}):
     * {@code type} and {@code function} compared exactly, {@code action} a value or a list that
     * holds {@code Execute}, and {@code domain} equal to the tenant ignoring case. The same power
     * with {@code type: domain} is an organization administrator, not a tenant administrator.
     * Each field is read from itself or, when absent, from its {@code tmf_} alias; a power whose
     * field and alias differ is ignored, as the Issuer's {@code JwtCallerProvider} does.
     */
    static boolean hasTenantAdministratorPower(Object powerClaim, String tenant) {
        if (!(powerClaim instanceof Collection<?> powers)) {
            return false;
        }
        return powers.stream()
                .filter(Map.class::isInstance)
                .map(power -> (Map<?, ?>) power)
                .filter(power -> !hasConflictingAlias(power))
                .anyMatch(power -> ORGANIZATION_POWER_TYPE.equals(field(power, "type"))
                        && ONBOARDING_FUNCTION.equals(field(power, "function"))
                        && hasAction(field(power, "action"))
                        && field(power, "domain") instanceof String domain
                        && domain.equalsIgnoreCase(tenant));
    }

    private static Object field(Map<?, ?> power, String name) {
        var value = power.get(name);
        return value != null ? value : power.get(ALIAS_PREFIX + name);
    }

    private static boolean hasConflictingAlias(Map<?, ?> power) {
        return POWER_FIELDS.stream().anyMatch(name -> {
            var value = power.get(name);
            var alias = power.get(ALIAS_PREFIX + name);
            return value != null && alias != null && !value.equals(alias);
        });
    }

    private static boolean hasAction(Object action) {
        if (action instanceof String single) {
            return EXECUTE_ACTION.equals(single);
        }
        return action instanceof Collection<?> actions && actions.contains(EXECUTE_ACTION);
    }

    private static String callerOf(JWTClaimsSet claims) {
        var subject = Objects.requireNonNullElse(claims.getSubject(), "unknown");
        return subject.length() > MAX_CALLER_LENGTH ? subject.substring(0, MAX_CALLER_LENGTH) : subject;
    }

    private static boolean sameIssuer(String issuer, String expectedIssuer) {
        return issuer != null && expectedIssuer != null && stripSlash(issuer).equals(stripSlash(expectedIssuer));
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static SignedJWT parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw SystemTokenRejectedException.invalidToken("missing");
        }
        try {
            return SignedJWT.parse(rawToken);
        } catch (ParseException _) {
            throw SystemTokenRejectedException.invalidToken("malformed");
        }
    }

    private static JWTClaimsSet claims(SignedJWT token) {
        try {
            return token.getJWTClaimsSet();
        } catch (ParseException _) {
            throw SystemTokenRejectedException.invalidToken("malformed");
        }
    }

    private static void verifySignature(SignedJWT token, JWK key) {
        try {
            if (!(key instanceof ECKey ec)) {
                throw SystemTokenRejectedException.invalidToken("key_type");
            }
            JWSVerifier verifier = new ECDSAVerifier(ec.toECPublicKey());
            if (!token.verify(verifier)) {
                throw SystemTokenRejectedException.invalidToken("signature");
            }
        } catch (JOSEException _) {
            throw SystemTokenRejectedException.invalidToken("signature");
        }
    }

    private static <T> Mono<T> reject(SystemTokenRejectedException e) {
        return Mono.error(e);
    }
}
