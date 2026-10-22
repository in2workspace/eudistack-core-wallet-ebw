package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.SessionSettings;
import com.eudistack.ebw.domain.model.exception.TenantConfigMissingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

/** Unit tests for {@link WalletAuthSettingsService}: Relying Party keys, session limits and their clamp. */
@ExtendWith(MockitoExtension.class)
class WalletAuthSettingsServiceTest {

    @Mock private TenantConfigService tenantConfigService;

    private WalletAuthSettingsService service;

    @BeforeEach
    void setUp() {
        service = new WalletAuthSettingsService(tenantConfigService);
        lenient().when(tenantConfigService.getStringOrDefault(anyString(), anyString()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(1)));
    }

    private void config(String key, String value) {
        when(tenantConfigService.getStringOrDefault(eq(key), anyString())).thenReturn(Mono.just(value));
    }

    @Test
    void relyingParty_onlyRpId_usesDefaultNameAndOrigin() {
        // Arrange
        when(tenantConfigService.getStringOrThrow("ebw.webauthn.rp_id")).thenReturn(Mono.just(" sandbox.stg.eudistack.net "));

        // Act + Assert
        StepVerifier.create(service.relyingParty())
                .assertNext(rp -> {
                    assertThat(rp.rpId()).isEqualTo("sandbox.stg.eudistack.net");
                    assertThat(rp.rpName()).isEqualTo("EUDIStack Wallet");
                    assertThat(rp.origins()).containsExactly("https://sandbox.stg.eudistack.net");
                })
                .verifyComplete();
    }

    @Test
    void relyingParty_originsList_isTrimmedAndDeduplicated() {
        // Arrange
        when(tenantConfigService.getStringOrThrow("ebw.webauthn.rp_id")).thenReturn(Mono.just("dome.example"));
        config("ebw.webauthn.origins", "https://a.example , https://b.example,https://a.example,");

        // Act + Assert
        StepVerifier.create(service.relyingParty())
                .assertNext(rp -> assertThat(rp.origins()).containsExactly("https://a.example", "https://b.example"))
                .verifyComplete();
    }

    @Test
    void relyingParty_withoutRpId_fails() {
        // Arrange
        when(tenantConfigService.getStringOrThrow("ebw.webauthn.rp_id"))
                .thenReturn(Mono.error(new TenantConfigMissingException("t", "ebw.webauthn.rp_id")));

        // Act + Assert
        StepVerifier.create(service.relyingParty()).expectError(TenantConfigMissingException.class).verify();
    }

    @Test
    void session_nothingConfigured_usesTheDefaults() {
        StepVerifier.create(service.session()).expectNext(SessionSettings.defaults()).verifyComplete();
    }

    @Test
    void session_validValues_areUsed() {
        // Arrange
        config("ebw.session.idle_timeout", "PT30M");
        config("ebw.session.max_duration", "PT12H");

        // Act + Assert
        StepVerifier.create(service.session())
                .expectNext(new SessionSettings(Duration.ofMinutes(30), Duration.ofHours(12)))
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource({
            "PT2H, PT8H, PT5M, PT8H",      // idle above PT1H
            "PT15M, PT48H, PT15M, PT8H",   // max above PT24H: the valid idle is kept
            "nonsense, PT8H, PT5M, PT8H",  // not ISO-8601
            "-PT5M, PT8H, PT5M, PT8H",     // negative
            "PT0S, PT8H, PT5M, PT8H",      // zero
            "PT1H, PT30M, PT5M, PT8H"      // idle longer than max: both defaults
    })
    void session_outOfRange_fallsBackToTheDefaults(String idle, String max, String expectedIdle, String expectedMax) {
        // Arrange
        config("ebw.session.idle_timeout", idle);
        config("ebw.session.max_duration", max);

        // Act + Assert
        StepVerifier.create(service.session())
                .expectNext(new SessionSettings(Duration.parse(expectedIdle), Duration.parse(expectedMax)))
                .verifyComplete();
    }
}
