package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.exception.RateLimitExceededException;
import com.eudistack.ebw.domain.model.exception.UserAlreadyRegisteredException;
import com.eudistack.ebw.domain.model.exception.UserNotFoundException;
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
        boolean isLogin = "login".equalsIgnoreCase(mode);

        Mono<Void> userCheck = isLogin
                ? userRepository.findByEmail(email)
                        .switchIfEmpty(Mono.error(new UserNotFoundException()))
                        .then()
                : userRepository.findByEmail(email)
                        .flatMap(u -> Mono.<Void>error(new UserAlreadyRegisteredException()))
                        .then();

        return emailRateLimiter.checkRegisterRate(email)
                .then(userCheck)
                .then(otpService.generateAndSend(email))
                .onErrorResume(e -> !(e instanceof RateLimitExceededException)
                                && !(e instanceof UserAlreadyRegisteredException)
                                && !(e instanceof UserNotFoundException), e -> {
                    log.warn("Failed to send OTP", e);
                    return Mono.empty();
                });
    }
}
