package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.EmailLanguage;
import com.eudistack.ebw.domain.model.EmailSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.DateTimeException;
import java.time.ZoneId;

/**
 * Per-tenant email settings, read from {@code tenant_config} (EUD-8 design §2.8, §5).
 *
 * <ul>
 *   <li>{@value #DEFAULT_LOCALE}: language of the emails when the holder's is unknown, and always of the alert
 *       to the security contact: {@code es} (default), {@code ca} or {@code en}. Any other value is ignored.</li>
 *   <li>{@value #TIMEZONE}: IANA time zone of the dates in the emails, default {@code Europe/Madrid}. An
 *       invalid value is ignored.</li>
 * </ul>
 */
public class EmailSettingsService {

    public static final String DEFAULT_LOCALE = "ebw.default_locale";
    public static final String TIMEZONE = "ebw.timezone";

    private static final Logger log = LoggerFactory.getLogger(EmailSettingsService.class);

    private final TenantConfigService tenantConfigService;

    public EmailSettingsService(TenantConfigService tenantConfigService) {
        this.tenantConfigService = tenantConfigService;
    }

    /** Settings of the current tenant, with the defaults for missing or invalid values. */
    public Mono<EmailSettings> current() {
        return Mono.zip(
                        tenantConfigService.getStringOrDefault(DEFAULT_LOCALE, ""),
                        tenantConfigService.getStringOrDefault(TIMEZONE, ""))
                .map(tuple -> new EmailSettings(parseLanguage(tuple.getT1()), parseZone(tuple.getT2())));
    }

    private static String parseLanguage(String raw) {
        if (raw == null || raw.isBlank()) {
            return EmailLanguage.DEFAULT;
        }
        return EmailLanguage.parse(raw).orElseGet(() -> {
            log.warn("tenant_config '{}' must be one of {}; using {}", DEFAULT_LOCALE, EmailLanguage.SUPPORTED,
                    EmailLanguage.DEFAULT);
            return EmailLanguage.DEFAULT;
        });
    }

    private static ZoneId parseZone(String raw) {
        if (raw == null || raw.isBlank()) {
            return EmailSettings.DEFAULT_ZONE;
        }
        try {
            return ZoneId.of(raw.strip());
        } catch (DateTimeException _) {
            log.warn("tenant_config '{}' is not a time zone; using {}", TIMEZONE, EmailSettings.DEFAULT_ZONE);
            return EmailSettings.DEFAULT_ZONE;
        }
    }
}
