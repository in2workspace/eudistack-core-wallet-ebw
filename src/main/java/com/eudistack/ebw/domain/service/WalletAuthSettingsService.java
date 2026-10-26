package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.SessionSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;

/**
 * Per-tenant WebAuthn Relying Party and session settings, read from {@code tenant_config}.
 *
 * <ul>
 *   <li>{@value #RP_ID} (required): canonical wallet domain of the tenant. Never derived from
 *       the {@code Host} header: without it, registration and sign-in fail.</li>
 *   <li>{@value #RP_NAME}: name shown by the passkey managers, default {@value #DEFAULT_RP_NAME}.</li>
 *   <li>{@value #ORIGINS}: comma-separated full origins of the Wallet App, default
 *       {@code https://<rp_id>}.</li>
 *   <li>{@value #IDLE_TIMEOUT} / {@value #MAX_DURATION}: ISO-8601 durations, default
 *       {@code PT5M} / {@code PT8H}, at most {@code PT1H} / {@code PT24H}, and the inactivity
 *       period not longer than the maximum duration. The inactivity period is at least the access
 *       token lifetime: the Wallet App renews 30 s before the access token expires, so a shorter
 *       refresh token would expire first and end the session of an active user.</li>
 * </ul>
 */
public class WalletAuthSettingsService {

    public static final String RP_ID = "ebw.webauthn.rp_id";
    public static final String RP_NAME = "ebw.webauthn.rp_name";
    public static final String ORIGINS = "ebw.webauthn.origins";
    public static final String IDLE_TIMEOUT = "ebw.session.idle_timeout";
    public static final String MAX_DURATION = "ebw.session.max_duration";
    public static final String DEFAULT_RP_NAME = "EUDIStack Wallet";
    /** Upper bounds of the tenant session limits; a longer value falls back to the default. */
    public static final Duration MAX_IDLE_TIMEOUT = Duration.ofHours(1);
    public static final Duration MAX_MAX_DURATION = Duration.ofHours(24);

    private static final Logger log = LoggerFactory.getLogger(WalletAuthSettingsService.class);

    private final TenantConfigService tenantConfigService;
    /** Lower bound of the inactivity period: the access token lifetime. */
    private final Duration minIdleTimeout;
    private final Duration defaultIdleTimeout;

    public WalletAuthSettingsService(TenantConfigService tenantConfigService, Duration accessTokenTtl) {
        this.tenantConfigService = tenantConfigService;
        this.minIdleTimeout = accessTokenTtl;
        this.defaultIdleTimeout = SessionSettings.DEFAULT_IDLE_TIMEOUT.compareTo(accessTokenTtl) < 0
                ? accessTokenTtl : SessionSettings.DEFAULT_IDLE_TIMEOUT;
    }

    /**
     * Relying Party of the current tenant.
     *
     * @return error {@link com.eudistack.ebw.domain.model.exception.TenantConfigMissingException}
     *         when the tenant has no {@value #RP_ID}
     */
    public Mono<RelyingPartySettings> relyingParty() {
        return tenantConfigService.getStringOrThrow(RP_ID)
                .map(String::trim)
                .flatMap(rpId -> Mono.zip(
                                tenantConfigService.getStringOrDefault(RP_NAME, DEFAULT_RP_NAME),
                                tenantConfigService.getStringOrDefault(ORIGINS, ""))
                        .map(tuple -> new RelyingPartySettings(rpId, tuple.getT1().trim(),
                                parseOrigins(tuple.getT2(), rpId))));
    }

    /** Session limits of the current tenant, with the defaults for missing or invalid values. */
    public Mono<SessionSettings> session() {
        return Mono.zip(
                        tenantConfigService.getStringOrDefault(IDLE_TIMEOUT, ""),
                        tenantConfigService.getStringOrDefault(MAX_DURATION, ""))
                .map(tuple -> {
                    var idle = parseDuration(IDLE_TIMEOUT, tuple.getT1(), defaultIdleTimeout, minIdleTimeout,
                            MAX_IDLE_TIMEOUT);
                    var max = parseDuration(MAX_DURATION, tuple.getT2(), SessionSettings.DEFAULT_MAX_DURATION,
                            Duration.ZERO, MAX_MAX_DURATION);
                    if (idle.compareTo(max) > 0) {
                        log.warn("tenant_config '{}' is longer than '{}'; using the defaults", IDLE_TIMEOUT,
                                MAX_DURATION);
                        return new SessionSettings(defaultIdleTimeout, SessionSettings.DEFAULT_MAX_DURATION);
                    }
                    return new SessionSettings(idle, max);
                });
    }

    private static List<String> parseOrigins(String raw, String rpId) {
        var origins = Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isEmpty())
                .distinct()
                .toList();
        return origins.isEmpty() ? List.of("https://" + rpId) : origins;
    }

    private static Duration parseDuration(String key, String raw, Duration defaultValue, Duration lowerBound,
                                          Duration upperBound) {
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            var value = Duration.parse(raw.trim());
            if (value.isNegative() || value.isZero() || value.compareTo(lowerBound) < 0
                    || value.compareTo(upperBound) > 0) {
                log.warn("tenant_config '{}' must be positive, at least {} and at most {}; using default {}", key,
                        lowerBound, upperBound, defaultValue);
                return defaultValue;
            }
            return value;
        } catch (DateTimeParseException _) {
            log.warn("tenant_config '{}' is not an ISO-8601 duration; using default {}", key, defaultValue);
            return defaultValue;
        }
    }
}
