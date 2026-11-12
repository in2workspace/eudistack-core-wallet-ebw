package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/** Unit tests for {@link OnboardingSettingsService}: defaults, ttl clamp, unknown mode and signup URL. */
@ExtendWith(MockitoExtension.class)
class OnboardingSettingsServiceTest {

    @Mock private TenantConfigService tenantConfigService;

    private OnboardingSettingsService service;

    @BeforeEach
    void setUp() {
        service = new OnboardingSettingsService(tenantConfigService);
        lenient().when(tenantConfigService.getStringOrDefault(anyString(), anyString()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(1)));
    }

    private void config(String key, String value) {
        when(tenantConfigService.getStringOrDefault(eq(key), anyString())).thenReturn(Mono.just(value));
    }

    @Test
    void current_noOnboardingKeys_disabledOpenWithDefaultTtl() {
        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> {
                    assertThat(settings.enabled()).isFalse();
                    assertThat(settings.ttl()).isEqualTo(Duration.ofMinutes(5));
                    assertThat(settings.registrationTtl()).isEqualTo(Duration.ofMinutes(30));
                    assertThat(settings.securityContact()).isNull();
                    assertThat(settings.mode()).isEqualTo(OnboardingMode.OPEN);
                    assertThat(settings.signupUrl()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void current_allKeys_parsesEveryValue() {
        // Arrange
        config(OnboardingSettingsService.ENABLED, "TRUE");
        config(OnboardingSettingsService.TTL, "PT2M");
        config(OnboardingSettingsService.REGISTRATION_TTL, "PT1H");
        config(OnboardingSettingsService.SECURITY_CONTACT, " security@example.org ");
        config(OnboardingSettingsService.MODE, "restricted");
        config(OnboardingSettingsService.SIGNUP_URL, "https://portal.example.org/alta");

        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> assertThat(settings).isEqualTo(new OnboardingSettings(true,
                        Duration.ofMinutes(2), Duration.ofHours(1), "security@example.org", OnboardingMode.RESTRICTED,
                        "https://portal.example.org/alta")))
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource({"PT10M,PT10M", "PT11M,PT5M", "PT0S,PT5M", "-PT1M,PT5M", "300,PT5M", "nonsense,PT5M"})
    void current_ttl_isClampedToDefault(String raw, String expected) {
        // Arrange
        config(OnboardingSettingsService.TTL, raw);

        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> assertThat(settings.ttl()).isEqualTo(Duration.parse(expected)))
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource({"PT10M,PT10M", "PT1H,PT1H", "PT1H1S,PT30M", "PT24H,PT30M", "P1D,PT30M", "PT0S,PT30M",
            "-PT1M,PT30M", "1800,PT30M", "nonsense,PT30M"})
    void current_registrationTtl_isAtMostOneHourElseDefault(String raw, String expected) {
        // Arrange: P8, provisional figure
        config(OnboardingSettingsService.REGISTRATION_TTL, raw);

        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> assertThat(settings.registrationTtl()).isEqualTo(Duration.parse(expected)))
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource({"open,OPEN", "OPEN,OPEN", "restricted,RESTRICTED", "closed,RESTRICTED", "' ',OPEN"})
    void current_mode_unknownValueIsRestricted(String raw, OnboardingMode expected) {
        // Arrange
        config(OnboardingSettingsService.MODE, raw);

        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> assertThat(settings.mode()).isEqualTo(expected))
                .verifyComplete();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://portal.example.org/", "portal.example.org", "https://", "https://exa mple.org"})
    void current_signupUrlNotHttps_isIgnored(String raw) {
        // Arrange
        config(OnboardingSettingsService.SIGNUP_URL, raw);

        // Act + Assert
        StepVerifier.create(service.current())
                .assertNext(settings -> assertThat(settings.signupUrl()).isNull())
                .verifyComplete();
    }
}
