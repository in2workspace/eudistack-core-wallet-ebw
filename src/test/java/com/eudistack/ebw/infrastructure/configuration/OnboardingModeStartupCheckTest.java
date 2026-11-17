package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.Mockito.when;

/** Unit tests for {@link OnboardingModeStartupCheck} (EC-08). */
@ExtendWith(MockitoExtension.class)
class OnboardingModeStartupCheckTest {

    @Mock private ActiveTenantDirectory tenantDirectory;
    @Mock private OnboardingSettingsService settingsService;

    private OnboardingModeStartupCheck check;

    @BeforeEach
    void setUp() {
        check = new OnboardingModeStartupCheck(tenantDirectory, settingsService);
    }

    @Test
    void misconfiguredRestrictedTenants_mixedTenants_reportsOnlyRestrictedWithoutTicketOrSignupUrl() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("open", "complete", "noticket", "nourl", "broken"));
        when(settingsService.current()).thenReturn(Mono.deferContextual(ctx -> {
            String tenant = ctx.get(ReactorContextKeys.TENANT_DOMAIN);
            return switch (tenant) {
                case "open" -> Mono.just(settings(false, OnboardingMode.OPEN, null));
                case "complete" -> Mono.just(settings(true, OnboardingMode.RESTRICTED, "https://a.example/"));
                case "noticket" -> Mono.just(settings(false, OnboardingMode.RESTRICTED, "https://a.example/"));
                case "nourl" -> Mono.just(settings(true, OnboardingMode.RESTRICTED, null));
                default -> Mono.error(new IllegalStateException("db down"));
            };
        }));

        // Act + Assert
        StepVerifier.create(check.misconfiguredRestrictedTenants())
                .expectNext(List.of("noticket", "nourl"))
                .verifyComplete();
    }

    @Test
    void tenantsWithoutWalletUrl_mixedTenants_reportsOnlyEnabledWithoutWalletUrl() {
        // Arrange: task 44
        when(tenantDirectory.activeTenants()).thenReturn(Flux.just("disabled", "complete", "nowallet", "broken"));
        when(settingsService.current()).thenReturn(Mono.deferContextual(ctx -> {
            String tenant = ctx.get(ReactorContextKeys.TENANT_DOMAIN);
            return switch (tenant) {
                case "disabled" -> Mono.just(settings(false, OnboardingMode.OPEN, null));
                case "complete" -> Mono.just(new OnboardingSettings(true, OnboardingSettings.DEFAULT_TTL,
                        OnboardingSettings.DEFAULT_REGISTRATION_TTL, null, OnboardingMode.OPEN, null,
                        "https://complete.example/wallet"));
                case "nowallet" -> Mono.just(settings(true, OnboardingMode.OPEN, null));
                default -> Mono.error(new IllegalStateException("db down"));
            };
        }));

        // Act + Assert
        StepVerifier.create(check.tenantsWithoutWalletUrl())
                .expectNext(List.of("nowallet"))
                .verifyComplete();
    }

    @Test
    void misconfiguredRestrictedTenants_registryUnavailable_completesWithoutFailing() {
        // Arrange
        when(tenantDirectory.activeTenants()).thenReturn(Flux.error(new IllegalStateException("no registry")));

        // Act + Assert
        StepVerifier.create(check.misconfiguredRestrictedTenants()).expectNext(List.of()).verifyComplete();
    }

    private static OnboardingSettings settings(boolean enabled, OnboardingMode mode, String signupUrl) {
        return new OnboardingSettings(enabled, OnboardingSettings.DEFAULT_TTL, OnboardingSettings.DEFAULT_REGISTRATION_TTL, null, mode, signupUrl,
                null);
    }
}
