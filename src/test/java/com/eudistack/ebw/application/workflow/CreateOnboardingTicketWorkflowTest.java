package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.CreateOnboardingTicketWorkflow.CreateOnboardingTicketCommand;
import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.exception.InvalidOnboardingRequestException;
import com.eudistack.ebw.domain.model.exception.OnboardingDisabledException;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link CreateOnboardingTicketWorkflow} (AC-01, AC-02, EC-03, ES-01, NFR-1, NFR-2). */
@ExtendWith(MockitoExtension.class)
class CreateOnboardingTicketWorkflowTest {

    private static final String OFFER = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.example%2Fo";

    @Mock private OnboardingSettingsService onboardingSettings;
    @Mock private WalletAuthSettingsService authSettings;
    @Mock private OnboardingPreregistrationRepository preregistrationRepository;
    @Mock private HashProvider hashProvider;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private AuditService auditService;

    private CreateOnboardingTicketWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new CreateOnboardingTicketWorkflow(onboardingSettings, authSettings, preregistrationRepository,
                hashProvider, randomGenerator, auditService);
        lenient().when(onboardingSettings.current()).thenReturn(Mono.just(settings(true)));
        lenient().when(authSettings.relyingParty()).thenReturn(Mono.just(new RelyingPartySettings(
                "sandbox.stg.eudistack.net", "EUDIStack Wallet", List.of("https://sandbox.stg.eudistack.net"))));
        lenient().when(randomGenerator.generateBytes(16)).thenReturn(new byte[16]);
        lenient().when(hashProvider.sha256(anyString())).thenReturn("h".repeat(64));
        lenient().when(preregistrationRepository.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        lenient().when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());
    }

    private static OnboardingSettings settings(boolean enabled) {
        return new OnboardingSettings(enabled, Duration.ofMinutes(5), null, OnboardingMode.OPEN, null);
    }

    @Test
    void create_enabledTenant_storesHashOnlyAndReturnsShortUrl() {
        // Arrange
        var captor = ArgumentCaptor.forClass(OnboardingPreregistration.class);

        // Act + Assert
        StepVerifier.create(workflow.create(new CreateOnboardingTicketCommand("ana@example.com", OFFER, null, "portal")))
                .assertNext(issued -> {
                    assertThat(issued.onboardingUrl())
                            .isEqualTo("https://sandbox.stg.eudistack.net/t/AAAAAAAAAAAAAAAAAAAAAA");
                    assertThat(issued.onboardingUrl().substring(issued.onboardingUrl().lastIndexOf('/') + 1))
                            .matches("^[A-Za-z0-9_-]{22}$");
                    assertThat(issued.expiresIn()).isEqualTo(300);
                })
                .verifyComplete();
        verify(preregistrationRepository).insert(captor.capture());
        var stored = captor.getValue();
        verify(hashProvider).sha256("AAAAAAAAAAAAAAAAAAAAAA");
        assertThat(stored.tokenHash()).isEqualTo("h".repeat(64));
        assertThat(stored.email()).isEqualTo("ana@example.com");
        assertThat(stored.credentialOffer()).isEqualTo(OFFER);
        assertThat(stored.requestedBy()).isEqualTo("portal");
        assertThat(stored.expiresAt()).isBetween(Instant.now().plusSeconds(290), Instant.now().plusSeconds(301));
        verify(auditService).record("onboarding_preregistration", stored.id(),
                AuthAuditEvents.PREREGISTRATION_CREATED, null, Map.of("requested_by", "portal"));
    }

    @Test
    void create_disabledTenant_failsWithoutStoringAnything() {
        // Arrange
        when(onboardingSettings.current()).thenReturn(Mono.just(settings(false)));

        // Act + Assert
        StepVerifier.create(workflow.create(new CreateOnboardingTicketCommand("ana@example.com", null, null, "portal")))
                .expectError(OnboardingDisabledException.class)
                .verify();
        verify(preregistrationRepository, never()).insert(any());
    }

    @Test
    void create_offerByValue_isInvalidRequest() {
        // Act + Assert
        StepVerifier.create(workflow.create(new CreateOnboardingTicketCommand("ana@example.com",
                        "openid-credential-offer://?credential_offer=%7B%7D", null, "portal")))
                .expectError(InvalidOnboardingRequestException.class)
                .verify();
        verify(preregistrationRepository, never()).insert(any());
    }

    @Test
    void create_withoutOfferAndShorterLifetime_isAccepted() {
        // Act + Assert
        StepVerifier.create(workflow.create(new CreateOnboardingTicketCommand("ana@example.com", null, 120, "portal")))
                .assertNext(issued -> assertThat(issued.expiresIn()).isEqualTo(120))
                .verifyComplete();
    }

    @ParameterizedTest
    @CsvSource({"60,60", "299,299", "300,300", "600,300", ",300"})
    void lifetime_systemMayOnlyShortenTheTenantTtl(Integer requested, long expected) {
        assertThat(CreateOnboardingTicketWorkflow.lifetime(Duration.ofMinutes(5), requested))
                .isEqualTo(Duration.ofSeconds(expected));
    }
}
