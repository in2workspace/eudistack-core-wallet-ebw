package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Unit tests for {@link RegisterWorkflow}: sends a code, creates nothing, anti-enumeration. */
@ExtendWith(MockitoExtension.class)
class RegisterWorkflowTest {

    private static final String EMAIL = "holder@example.com";

    @Mock private OtpService otpService;
    @Mock private EmailRateLimiter emailRateLimiter;
    @Mock private AuditService auditService;

    private RegisterWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new RegisterWorkflow(otpService, emailRateLimiter, auditService);
    }

    @Test
    void registerUser_validEmail_sendsCodeAndAuditsWithoutEmail() {
        // Arrange
        var verificationId = UUID.randomUUID();
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.generateAndSend(EMAIL)).thenReturn(Mono.just(verificationId));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.registerUser(EMAIL);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(auditService).record("email_verification", verificationId, AuthAuditEvents.EMAIL_CODE_REQUESTED,
                null, Map.of());
    }

    @Test
    void registerUser_rateLimited_propagatesTheLimit() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.error(new RateLimitExceededException(3600)));

        // Act
        var result = workflow.registerUser(EMAIL);

        // Assert
        StepVerifier.create(result).expectError(RateLimitExceededException.class).verify();
        verifyNoInteractions(otpService, auditService);
    }

    @Test
    void registerUser_sendFails_completesSilently() {
        // Arrange
        when(emailRateLimiter.checkRegisterRate(EMAIL)).thenReturn(Mono.empty());
        when(otpService.generateAndSend(EMAIL)).thenReturn(Mono.error(new IllegalStateException("smtp down")));

        // Act
        var result = workflow.registerUser(EMAIL);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verifyNoInteractions(auditService);
    }
}
