package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.EmailSettings;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.ZoneId;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for {@link EmailSettingsService}: {@code ebw.default_locale} and {@code ebw.timezone} (EUD-8 §2.8). */
class EmailSettingsServiceTest {

    private EmailSettingsService serviceWith(String locale, String zone) {
        var config = mock(TenantConfigService.class);
        when(config.getStringOrDefault(eq(EmailSettingsService.DEFAULT_LOCALE), anyString())).thenReturn(Mono.just(locale));
        when(config.getStringOrDefault(eq(EmailSettingsService.TIMEZONE), anyString())).thenReturn(Mono.just(zone));
        return new EmailSettingsService(config);
    }

    @Test
    void current_configuredValues_areUsed() {
        StepVerifier.create(serviceWith("ca", "Atlantic/Canary").current())
                .expectNext(new EmailSettings("ca", ZoneId.of("Atlantic/Canary")))
                .verifyComplete();
    }

    @Test
    void current_missingValues_areTheDefaults() {
        StepVerifier.create(serviceWith("", "").current()).expectNext(EmailSettings.DEFAULTS).verifyComplete();
    }

    @Test
    void current_invalidValues_fallBackToTheDefaults() {
        StepVerifier.create(serviceWith("fr", "Mars/Olympus").current())
                .expectNext(EmailSettings.DEFAULTS)
                .verifyComplete();
    }
}
