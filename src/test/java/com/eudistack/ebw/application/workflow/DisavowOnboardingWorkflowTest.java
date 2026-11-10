package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidDisavowalTokenException;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link DisavowOnboardingWorkflow} (AC-10, ES-06, FR-32). */
@ExtendWith(MockitoExtension.class)
class DisavowOnboardingWorkflowTest {

    private static final String TOKEN = "k".repeat(43);
    private static final String HASH = "h".repeat(64);
    private static final String EMAIL = "ana.garcia@cgcom.es";
    private static final String CONTACT = "security@cgcom.es";

    @Mock private OnboardingDisavowalRepository disavowalRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private OnboardingSettingsService onboardingSettings;
    @Mock private EmailSender emailSender;
    @Mock private HashProvider hashProvider;
    @Mock private TransactionRunner transactionRunner;
    @Mock private AuditService auditService;

    private DisavowOnboardingWorkflow workflow;
    private WalletUser account;
    private UUID passkeyId;
    private OnboardingDisavowal disavowal;

    @BeforeEach
    void setUp() {
        workflow = new DisavowOnboardingWorkflow(disavowalRepository, refreshTokenRepository, passkeyRepository,
                userRepository, onboardingSettings, emailSender, hashProvider, transactionRunner, auditService);
        account = WalletUser.create(EMAIL, new byte[WalletUser.USER_HANDLE_LENGTH]);
        passkeyId = UUID.randomUUID();
        disavowal = OnboardingDisavowal.issue(HASH, account.getId(), passkeyId, "portal-machine.cgcom.es",
                Instant.parse("2026-10-30T09:42:00Z"));
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(hashProvider.sha256(TOKEN)).thenReturn(HASH);
        lenient().when(disavowalRepository.consume(HASH)).thenReturn(Mono.just(disavowal));
        lenient().when(refreshTokenRepository.revokeByUserId(account.getId())).thenReturn(Mono.just(2L));
        var passkey = mock(UserPasskey.class);
        lenient().when(passkey.getId()).thenReturn(passkeyId);
        lenient().when(passkeyRepository.findByIdAndUserId(passkeyId, account.getId())).thenReturn(Mono.just(passkey));
        lenient().when(passkeyRepository.deleteById(passkeyId)).thenReturn(Mono.empty());
        lenient().when(userRepository.findById(account.getId())).thenReturn(Mono.just(account));
        lenient().when(onboardingSettings.current()).thenReturn(Mono.just(settings(CONTACT)));
        lenient().when(emailSender.sendOnboardingAlert(anyString(), any(), any())).thenReturn(Mono.empty());
        lenient().when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());
    }

    private static OnboardingSettings settings(String securityContact) {
        return new OnboardingSettings(true, Duration.ofMinutes(5), securityContact, OnboardingMode.OPEN, null);
    }

    @Test
    void disavow_validToken_endsTheSessionsRemovesThePasskeyAndAlertsTheTenant() {
        // Act
        StepVerifier.create(workflow.disavow(TOKEN)).verifyComplete();

        // Assert: AC-10
        verify(refreshTokenRepository).revokeByUserId(account.getId());
        verify(passkeyRepository).deleteById(passkeyId);
        verify(auditService).record("onboarding_disavowal", disavowal.id(), AuthAuditEvents.ONBOARDING_DISAVOWED,
                account.getId(), Map.of("requested_by", "portal-machine.cgcom.es", "passkey_removed", true));
        var alert = ArgumentCaptor.forClass(OnboardingAlert.class);
        verify(emailSender).sendOnboardingAlert(eq(CONTACT), alert.capture(), any());
        assertThat(alert.getValue().maskedEmail()).isEqualTo("a***@cgcom.es");
        assertThat(alert.getValue().registeredAt()).isEqualTo(disavowal.registeredAt());
    }

    @Test
    void disavow_theUndoRunsInOneTransaction() {
        // Act
        StepVerifier.create(workflow.disavow(TOKEN)).verifyComplete();

        // Assert
        verify(transactionRunner).inTransaction(any());
    }

    @Test
    void disavow_unknownUsedOrExpiredToken_isInvalidAndChangesNothing() {
        // Arrange: AC-10, a token already used or older than 7 days is not consumed
        when(disavowalRepository.consume(HASH)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.disavow(TOKEN)).expectError(InvalidDisavowalTokenException.class).verify();
        verify(refreshTokenRepository, never()).revokeByUserId(any());
        verify(emailSender, never()).sendOnboardingAlert(anyString(), any(), any());
    }

    @Test
    void disavow_passkeyAlreadyRemoved_stillEndsTheSessions() {
        // Arrange: the holder removed the passkey, or another account would own it
        when(passkeyRepository.findByIdAndUserId(passkeyId, account.getId())).thenReturn(Mono.empty());

        // Act
        StepVerifier.create(workflow.disavow(TOKEN)).verifyComplete();

        // Assert
        verify(refreshTokenRepository).revokeByUserId(account.getId());
        verify(passkeyRepository, never()).deleteById(any());
        verify(auditService).record("onboarding_disavowal", disavowal.id(), AuthAuditEvents.ONBOARDING_DISAVOWED,
                account.getId(), Map.of("requested_by", "portal-machine.cgcom.es", "passkey_removed", false));
    }

    @Test
    void disavow_alertFails_stillSucceedsAndTracesTheFailure() {
        // Arrange: ES-06
        when(emailSender.sendOnboardingAlert(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act
        StepVerifier.create(workflow.disavow(TOKEN)).verifyComplete();

        // Assert
        verify(passkeyRepository).deleteById(passkeyId);
        verify(auditService).record("onboarding_disavowal", disavowal.id(), AuthAuditEvents.ONBOARDING_ALERT_FAILED,
                account.getId(), Map.of("reason", "send_failed"));
    }

    @Test
    void disavow_tenantWithoutSecurityContact_tracesTheMissingAlert() {
        // Arrange
        when(onboardingSettings.current()).thenReturn(Mono.just(settings(null)));

        // Act
        StepVerifier.create(workflow.disavow(TOKEN)).verifyComplete();

        // Assert
        verify(emailSender, never()).sendOnboardingAlert(anyString(), any(), any());
        verify(auditService).record("onboarding_disavowal", disavowal.id(), AuthAuditEvents.ONBOARDING_ALERT_FAILED,
                account.getId(), Map.of("reason", "no_security_contact"));
    }

    @Test
    void mask_keepsTheFirstLetterAndTheDomain() {
        assertThat(OnboardingAlert.mask("ana.garcia@cgcom.es")).isEqualTo("a***@cgcom.es");
        assertThat(OnboardingAlert.mask("x")).isEqualTo("x***");
        assertThat(OnboardingAlert.mask(null)).isEqualTo("***");
    }
}
