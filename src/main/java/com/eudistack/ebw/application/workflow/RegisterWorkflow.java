package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Sends a one-time code to an email (FR-03). Creates nothing: the account is created when the
 * code is verified (FR-04). Same outcome whether the email has an account or not (FR-05): the
 * account is not even looked up. Only the per-email rate limit is reported to the caller.
 */
@Service
public class RegisterWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RegisterWorkflow.class);

    private final OtpService otpService;
    private final EmailRateLimiter emailRateLimiter;
    private final AuditService auditService;

    public RegisterWorkflow(OtpService otpService, EmailRateLimiter emailRateLimiter, AuditService auditService) {
        this.otpService = otpService;
        this.emailRateLimiter = emailRateLimiter;
        this.auditService = auditService;
    }

    public Mono<Void> registerUser(String email) {
        return emailRateLimiter.checkRegisterRate(email)
                .then(Mono.defer(() -> otpService.generateAndSend(email)))
                .flatMap(verificationId -> auditService.record(AuthAuditEvents.ENTITY_EMAIL_VERIFICATION,
                        verificationId, AuthAuditEvents.EMAIL_CODE_REQUESTED, null, Map.of()))
                .onErrorResume(e -> !(e instanceof RateLimitExceededException), e -> {
                    // Never log the email: the exception class is enough to diagnose.
                    log.warn("Failed to send a verification code: {}", e.getClass().getName());
                    return Mono.empty();
                });
    }
}
