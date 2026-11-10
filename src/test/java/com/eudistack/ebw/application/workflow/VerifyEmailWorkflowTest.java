package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.model.OnboardingMode;
import com.eudistack.ebw.domain.model.OnboardingSettings;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.DuplicateAccountException;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.NoAccountException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.support.TestPasskeys;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link VerifyEmailWorkflow}: account created on verification, ticket, never a session. */
@ExtendWith(MockitoExtension.class)
class VerifyEmailWorkflowTest {

    private static final String EMAIL = "holder@example.com";
    private static final String CODE = "123456";

    @Mock private OtpService otpService;
    @Mock private WalletUserRepository userRepository;
    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private RegistrationTicketService ticketService;
    @Mock private SecureRandomGenerator randomGenerator;
    @Mock private AuditService auditService;
    @Mock private EmailRateLimiter emailRateLimiter;
    @Mock private OnboardingSettingsService onboardingSettings;

    private VerifyEmailWorkflow workflow;
    private EmailVerification verification;

    @BeforeEach
    void setUp() {
        workflow = new VerifyEmailWorkflow(otpService, userRepository, passkeyRepository, ticketService,
                randomGenerator, auditService, emailRateLimiter, onboardingSettings);
        lenient().when(onboardingSettings.current()).thenReturn(Mono.just(onboarding(OnboardingMode.OPEN, null)));
        verification = EmailVerification.create(EMAIL, "hash", Instant.now().plusSeconds(600));
    }

    private static OnboardingSettings onboarding(OnboardingMode mode, String signupUrl) {
        return new OnboardingSettings(true, Duration.ofMinutes(5), OnboardingSettings.DEFAULT_REGISTRATION_TTL, null, mode, signupUrl);
    }

    private void validCode() {
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.just(verification));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        // Not reached when the restricted mode rejects an email without account.
        lenient().when(ticketService.issue(any())).thenReturn(Mono.just("raw-ticket"));
        when(emailRateLimiter.resetForEmail(EMAIL)).thenReturn(Mono.empty());
    }

    @Test
    void verifyEmail_unknownEmail_createsAccountWithRandomUserHandleAndReturnsTicket() {
        // Arrange
        validCode();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());
        when(randomGenerator.generateBytes(32)).thenReturn(TestPasskeys.randomBytes(32));
        when(userRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(passkeyRepository.countByUserId(any())).thenReturn(Mono.just(0L));

        // Act
        var result = workflow.verifyEmail(EMAIL, CODE);

        // Assert
        StepVerifier.create(result)
                .assertNext(issued -> {
                    assertThat(issued.ticket()).isEqualTo("raw-ticket");
                    assertThat(issued.expiresIn()).isEqualTo(300);
                    assertThat(issued.hasPasskeys()).isFalse();
                })
                .verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletUser.class);
        verify(userRepository).save(saved.capture());
        assertThat(saved.getValue().getWebauthnUserHandle()).hasSize(32);
        verify(auditService).record("user", saved.getValue().getId(), AuthAuditEvents.ACCOUNT_CREATED,
                saved.getValue().getId(), Map.of());
    }

    @Test
    void verifyEmail_existingAccountWithPasskeys_recognizesItWithoutDuplicating() {
        // Arrange
        validCode();
        var existing = TestPasskeys.user(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.just(existing));
        when(passkeyRepository.countByUserId(existing.getId())).thenReturn(Mono.just(2L));

        // Act
        var result = workflow.verifyEmail(EMAIL, CODE);

        // Assert
        StepVerifier.create(result).assertNext(issued -> assertThat(issued.hasPasskeys()).isTrue()).verifyComplete();
        verify(userRepository, never()).save(any());
        verify(auditService).record("user", existing.getId(), AuthAuditEvents.ACCOUNT_RECOGNIZED,
                existing.getId(), Map.of());
        verify(ticketService).issue(existing.getId());
    }

    @Test
    void verifyEmail_wrongCode_auditsRejectionAndNeverCreatesAccount() {
        // Arrange
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.error(new InvalidOtpException()));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.verifyEmail(EMAIL, CODE);

        // Assert
        StepVerifier.create(result).expectError(InvalidOtpException.class).verify();
        verify(auditService).record(eq("email_verification"), any(), eq(AuthAuditEvents.EMAIL_CODE_REJECTED),
                eq(null), eq(Map.of("reason", "invalid_code")));
        verify(userRepository, never()).findByEmail(anyString());
        verify(ticketService, never()).issue(any());
    }

    @Test
    void verifyEmail_expiredCode_auditsExpiredReason() {
        // Arrange
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.error(new OtpExpiredException()));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE)).expectError(OtpExpiredException.class).verify();
        verify(auditService).record(eq("email_verification"), any(), eq(AuthAuditEvents.EMAIL_CODE_REJECTED),
                eq(null), eq(Map.of("reason", "expired_code")));
    }

    @Test
    void verifyEmail_attemptsExhausted_auditsTooManyAttempts() {
        // Arrange
        when(emailRateLimiter.checkVerifyRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.verify(EMAIL, CODE)).thenReturn(Mono.error(new TooManyAttemptsException()));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE)).expectError(TooManyAttemptsException.class).verify();
        verify(auditService).record(eq("email_verification"), any(), eq(AuthAuditEvents.EMAIL_CODE_REJECTED),
                eq(null), eq(Map.of("reason", "too_many_attempts")));
    }

    @Test
    void verifyEmail_accountCreatedConcurrently_reusesTheExistingAccount() {
        // Arrange
        validCode();
        var existing = TestPasskeys.user(EMAIL);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty(), Mono.just(existing));
        when(randomGenerator.generateBytes(32)).thenReturn(TestPasskeys.randomBytes(32));
        when(userRepository.save(any())).thenReturn(Mono.error(new DuplicateAccountException()));
        when(passkeyRepository.countByUserId(existing.getId())).thenReturn(Mono.just(0L));

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE)).expectNextCount(1).verifyComplete();
        verify(ticketService).issue(existing.getId());
    }

    @Test
    void verifyEmail_restrictedModeUnknownEmail_createsNothingAndAnswersNoAccount() {
        // Arrange: AC-13, FR-34
        validCode();
        when(onboardingSettings.current())
                .thenReturn(Mono.just(onboarding(OnboardingMode.RESTRICTED, "https://portal.example.org/")));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(NoAccountException.class)
                        .extracting("signupUrl").isEqualTo("https://portal.example.org/"))
                .verify();
        verify(userRepository, never()).save(any());
        verify(ticketService, never()).issue(any());
        verify(auditService).record(eq("email_verification"), eq(verification.getId()),
                eq(AuthAuditEvents.ONBOARDING_WITHOUT_TICKET_REJECTED), isNull(), eq(Map.of()));
    }

    @Test
    void verifyEmail_restrictedModeWithoutSignupUrl_answersNoAccountWithoutIt() {
        // Arrange: EC-09
        validCode();
        when(onboardingSettings.current()).thenReturn(Mono.just(onboarding(OnboardingMode.RESTRICTED, null)));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .expectErrorSatisfies(e -> assertThat(((NoAccountException) e).getSignupUrl()).isNull())
                .verify();
    }

    @Test
    void verifyEmail_restrictedModeExistingAccount_givesTheTicketAsInOpenMode() {
        // Arrange: AC-14, FR-35
        validCode();
        var account = WalletUser.create(EMAIL, TestPasskeys.randomBytes(32));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.just(account));
        when(passkeyRepository.countByUserId(account.getId())).thenReturn(Mono.just(1L));

        // Act + Assert
        StepVerifier.create(workflow.verifyEmail(EMAIL, CODE))
                .assertNext(issued -> assertThat(issued.ticket()).isEqualTo("raw-ticket"))
                .verifyComplete();
        verify(onboardingSettings, never()).current();
    }
}
