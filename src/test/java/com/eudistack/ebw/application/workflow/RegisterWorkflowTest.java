package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RegisterWorkflow} — unified find-or-create + OTP send, rate limit surfaced,
 * any other failure swallowed (anti-enumeration).
 */
@ExtendWith(MockitoExtension.class)
class RegisterWorkflowTest {

    private static final String EMAIL = "holder@example.com";

    @Mock private OtpService otpService;
    @Mock private EmailRateLimiter emailRateLimiter;
    @Mock private WalletUserRepository userRepository;
    @Mock private AuditService auditService;

    private RegisterWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new RegisterWorkflow(otpService, emailRateLimiter, userRepository, auditService);
    }

    @Test
    void registerUser_unknownEmail_createsUserAuditsAndSendsOtp() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.save(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(otpService.generateAndSend(EMAIL)).thenReturn(Mono.empty());

        // Act
        var result = workflow.registerUser(EMAIL, "register");

        // Assert
        StepVerifier.create(result).verifyComplete();
        var saved = ArgumentCaptor.forClass(WalletUser.class);
        verify(userRepository).save(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo(EMAIL);
        verify(auditService).record("user", saved.getValue().getId(), "REGISTRATION_INITIATED",
                saved.getValue().getId(), Map.of());
        verify(otpService).generateAndSend(EMAIL);
    }

    @Test
    void registerUser_existingEmail_reusesUserWithoutPersistingANewOne() {
        // Arrange
        var existing = WalletUser.create(EMAIL);
        var saveProbe = PublisherProbe.<WalletUser>empty();
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.just(existing));
        when(userRepository.save(any())).thenReturn(saveProbe.mono());
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(otpService.generateAndSend(EMAIL)).thenReturn(Mono.empty());

        // Act
        var result = workflow.registerUser(EMAIL, "login");

        // Assert
        StepVerifier.create(result).verifyComplete();
        saveProbe.assertWasNotSubscribed();
        verify(auditService).record("user", existing.getId(), "REGISTRATION_INITIATED", existing.getId(), Map.of());
    }

    @Test
    void registerUser_rateLimitExceeded_propagatesErrorWithoutSendingOtp() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.error(new RateLimitExceededException(3600)));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.save(any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.registerUser(EMAIL, null);

        // Assert
        StepVerifier.create(result)
                .expectError(RateLimitExceededException.class)
                .verify();
        verifyNoInteractions(otpService, auditService);
    }

    @Test
    void registerUser_otpDeliveryFails_completesSilently() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.just(WalletUser.create(EMAIL)));
        when(userRepository.save(any())).thenReturn(Mono.empty());
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(otpService.generateAndSend(EMAIL)).thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act
        var result = workflow.registerUser(EMAIL, null);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }

    @Test
    void registerUser_userLookupFails_doesNotSendOtpAndCompletesSilently() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(userRepository.findByEmail(EMAIL)).thenReturn(Mono.error(new IllegalStateException("db down")));
        when(userRepository.save(any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.registerUser(EMAIL, null);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(otpService, never()).generateAndSend(any());
    }
}
