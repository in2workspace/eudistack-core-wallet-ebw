package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
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
    private final WalletUserRepository userRepository;

    public RegisterWorkflow(OtpService otpService, EmailRateLimiter emailRateLimiter,
                            WalletUserRepository userRepository) {
        this.otpService = otpService;
        this.emailRateLimiter = emailRateLimiter;
        this.userRepository = userRepository;
    }

    public Mono<Void> registerUser(String email, String mode) {
        // Unified flow: find-or-create. No distinction between login and register.
        // If the email exists the user continues; if not, a new account is created.
        // The `mode` parameter is accepted for API compatibility but ignored.
        return emailRateLimiter.checkRegisterRate(email)
                .then(userRepository.findByEmail(email)
                        .switchIfEmpty(userRepository.save(WalletUser.create(email)))
                        .then())
                .then(otpService.generateAndSend(email))
                .onErrorResume(e -> !(e instanceof RateLimitExceededException), e -> {
                    log.warn("Failed to send OTP to {}", email, e);
                    return Mono.empty();
                });
    }
}
