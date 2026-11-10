package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link NotifyOnboardingAccountCreatedWorkflow} (FR-29, ES-06, decisions P5 and P6). */
@ExtendWith(MockitoExtension.class)
class NotifyOnboardingAccountCreatedWorkflowTest {

    private static final RelyingPartySettings RP = new RelyingPartySettings("cgcom.eudistack.net", "Wallet",
            List.of("https://cgcom.eudistack.net"));

    @Mock private OnboardingDisavowalRepository disavowalRepository;
    @Mock private WalletUserRepository userRepository;
    @Mock private WalletAuthSettingsService authSettings;
    @Mock private EmailSender emailSender;
    @Mock private HashProvider hashProvider;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private AuditService auditService;

    private NotifyOnboardingAccountCreatedWorkflow workflow;
    private WalletUser account;
    private UUID passkeyId;
    private OnboardingDisavowal withToken;
    private String expectedToken;

    @BeforeEach
    void setUp() {
        workflow = new NotifyOnboardingAccountCreatedWorkflow(disavowalRepository, userRepository, authSettings,
                emailSender, hashProvider, randomGenerator, auditService);
        account = WalletUser.create("ana@cgcom.es", new byte[WalletUser.USER_HANDLE_LENGTH]);
        passkeyId = UUID.randomUUID();
        var bytes = new byte[32];
        bytes[0] = 9;
        expectedToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        var pending = OnboardingDisavowal.pending(account.getId(), passkeyId, "portal-machine.cgcom.es",
                Instant.parse("2026-10-30T09:42:00Z"));
        withToken = new OnboardingDisavowal(pending.id(), "hash", pending.userId(), pending.passkeyId(),
                pending.requestedBy(), pending.registeredAt(), Instant.now().plus(Duration.ofDays(7)), null,
                pending.createdAt());
        lenient().when(randomGenerator.generateBytes(32)).thenReturn(bytes);
        lenient().when(hashProvider.sha256(expectedToken)).thenReturn("hash");
        lenient().when(disavowalRepository.assignToken(eq(passkeyId), eq("hash"), any())).thenReturn(Mono.just(withToken));
        lenient().when(userRepository.findById(account.getId())).thenReturn(Mono.just(account));
        lenient().when(authSettings.relyingParty()).thenReturn(Mono.just(RP));
        lenient().when(emailSender.sendAccountCreatedNotice(anyString(), any(), any())).thenReturn(Mono.empty());
        lenient().when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());
    }

    @Test
    void notify_pendingRow_givesItTheTokenAndEmailsTheLink() {
        // Act
        StepVerifier.create(workflow.notify(passkeyId, "iPhone · Safari")).verifyComplete();

        // Assert: decision P6, only the hash is stored and the link carries the raw token
        var expiresAt = ArgumentCaptor.forClass(Instant.class);
        verify(disavowalRepository).assignToken(eq(passkeyId), eq("hash"), expiresAt.capture());
        assertThat(expiresAt.getValue()).isCloseTo(Instant.now().plus(Duration.ofDays(7)),
                within(5, java.time.temporal.ChronoUnit.SECONDS));
        var notice = ArgumentCaptor.forClass(AccountCreatedNotice.class);
        verify(emailSender).sendAccountCreatedNotice(eq("ana@cgcom.es"), notice.capture(), any());
        assertThat(notice.getValue().disavowalUrl())
                .isEqualTo("https://cgcom.eudistack.net/no-he-sido-yo#" + expectedToken);
        assertThat(notice.getValue().deviceName()).isEqualTo("iPhone · Safari");
        assertThat(notice.getValue().createdAt()).isEqualTo(Instant.parse("2026-10-30T09:42:00Z"));
        verify(auditService).record("onboarding_disavowal", withToken.id(), AuthAuditEvents.ONBOARDING_NOTICE_SENT,
                account.getId(), Map.of());
    }

    @Test
    void notify_rowAlreadyWithTokenOrNone_sendsNothing() {
        // Arrange: the email already went out, or the passkey was not registered with a ticket
        when(disavowalRepository.assignToken(eq(passkeyId), eq("hash"), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.notify(passkeyId, "Passkey")).verifyComplete();
        verify(emailSender, never()).sendAccountCreatedNotice(anyString(), any(), any());
    }

    @Test
    void notify_emailFails_tracesItAndCompletes() {
        // Arrange: ES-06, the onboarding stands
        when(emailSender.sendAccountCreatedNotice(anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act + Assert
        StepVerifier.create(workflow.notify(passkeyId, "Passkey")).verifyComplete();
        verify(auditService).record("onboarding_disavowal", withToken.id(), AuthAuditEvents.ONBOARDING_NOTICE_FAILED,
                account.getId(), Map.of());
    }

    @Test
    void notify_tokenCannotBeAssigned_completesWithoutFailing() {
        // Arrange: a database error never fails the registration that called it
        when(disavowalRepository.assignToken(eq(passkeyId), eq("hash"), any()))
                .thenReturn(Mono.error(new IllegalStateException("db down")));

        // Act + Assert
        StepVerifier.create(workflow.notify(passkeyId, "Passkey")).verifyComplete();
    }
}
