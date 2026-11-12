package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.format.DateTimeParseException;

/**
 * Per-tenant onboarding settings, read from {@code tenant_config} (design §2.6, §2.7). The keys
 * carry the {@code ebw.} prefix of the other Wallet Unit Service keys (EUD-315 decision P3).
 *
 * <ul>
 *   <li>{@value #ENABLED}: {@code true} to accept onboarding ticket requests; default {@code false}.</li>
 *   <li>{@value #TTL}: ISO-8601 lifetime of a pre-registration, default {@code PT5M}, at most
 *       {@code PT10M}; an invalid or out-of-range value falls back to the default.</li>
 *   <li>{@value #REGISTRATION_TTL}: ISO-8601 time to create the passkey after the redemption, default
 *       {@code PT30M}, at most {@code PT1H} (both provisional, EUD-315 decision P8); an invalid or
 *       out-of-range value falls back to the default.</li>
 *   <li>{@value #SECURITY_CONTACT}: email warned when an account holder disavows an onboarding.</li>
 *   <li>{@value #MODE}: {@code open} (default) or {@code restricted}; an unknown value is
 *       {@code restricted}.</li>
 *   <li>{@value #SIGNUP_URL}: onboarding address of the tenant, only if it is an https URL.</li>
 * </ul>
 */
public class OnboardingSettingsService {

    public static final String ENABLED = "ebw.onboarding.enabled";
    public static final String TTL = "ebw.onboarding.ttl";
    public static final String REGISTRATION_TTL = "ebw.onboarding.registration_ttl";
    public static final String SECURITY_CONTACT = "ebw.onboarding.security_contact";
    public static final String MODE = "ebw.onboarding.mode";
    public static final String SIGNUP_URL = "ebw.onboarding.signup_url";

    private static final Logger log = LoggerFactory.getLogger(OnboardingSettingsService.class);

    private final TenantConfigService tenantConfigService;

    public OnboardingSettingsService(TenantConfigService tenantConfigService) {
        this.tenantConfigService = tenantConfigService;
    }

    /** Settings of the current tenant, with the defaults for missing or invalid values. */
    public Mono<OnboardingSettings> current() {
        return Mono.zip(
                        tenantConfigService.getStringOrDefault(ENABLED, ""),
                        tenantConfigService.getStringOrDefault(TTL, ""),
                        tenantConfigService.getStringOrDefault(SECURITY_CONTACT, ""),
                        tenantConfigService.getStringOrDefault(MODE, ""),
                        tenantConfigService.getStringOrDefault(SIGNUP_URL, ""),
                        tenantConfigService.getStringOrDefault(REGISTRATION_TTL, ""))
                .map(tuple -> new OnboardingSettings(
                        "true".equalsIgnoreCase(tuple.getT1().trim()),
                        parseDuration(tuple.getT2(), TTL, OnboardingSettings.DEFAULT_TTL, OnboardingSettings.MAX_TTL),
                        parseDuration(tuple.getT6(), REGISTRATION_TTL, OnboardingSettings.DEFAULT_REGISTRATION_TTL,
                                OnboardingSettings.MAX_REGISTRATION_TTL),
                        blankToNull(tuple.getT3()),
                        parseMode(tuple.getT4()),
                        parseSignupUrl(tuple.getT5())));
    }

    private static Duration parseDuration(String raw, String key, Duration defaultValue, Duration max) {
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            var value = Duration.parse(raw.trim());
            if (value.isNegative() || value.isZero() || value.compareTo(max) > 0) {
                log.warn("tenant_config '{}' must be positive and at most {}; using default {}", key, max,
                        defaultValue);
                return defaultValue;
            }
            return value;
        } catch (DateTimeParseException _) {
            log.warn("tenant_config '{}' is not an ISO-8601 duration; using default {}", key, defaultValue);
            return defaultValue;
        }
    }

    private static OnboardingMode parseMode(String raw) {
        if (!OnboardingMode.isKnown(raw)) {
            log.warn("tenant_config '{}' has an unknown value; the tenant is treated as restricted", MODE);
        }
        return OnboardingMode.parse(raw);
    }

    private static String parseSignupUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            var uri = new URI(raw.trim());
            if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) {
                return uri.toString();
            }
        } catch (URISyntaxException _) {
            // Logged below.
        }
        log.warn("tenant_config '{}' is not an https URL; it is ignored", SIGNUP_URL);
        return null;
    }

    private static String blankToNull(String raw) {
        return raw == null || raw.isBlank() ? null : raw.trim();
    }
}
