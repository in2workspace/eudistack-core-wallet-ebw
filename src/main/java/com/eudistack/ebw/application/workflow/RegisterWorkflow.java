package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RegisterWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RegisterWorkflow.class);

    private final OtpService otpService;
    private final EmailRateLimiter emailRateLimiter;

    public RegisterWorkflow(OtpService otpService, EmailRateLimiter emailRateLimiter) {
        this.otpService = otpService;
        this.emailRateLimiter = emailRateLimiter;
    }

    public Mono<Void> registerUser(String email) {
        return emailRateLimiter.checkRegisterRate(email)
                .then(otpService.generateAndSend(email))
                .onErrorResume(e -> !(e instanceof RateLimitExceededException), e -> {
                    log.warn("Failed to send OTP for registration", e);
                    return Mono.empty();
                });
    }
}
