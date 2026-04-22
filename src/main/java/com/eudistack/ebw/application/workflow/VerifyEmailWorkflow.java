package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthTokenPair;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class VerifyEmailWorkflow {

    private final OtpService otpService;
    private final AuthTokenService authTokenService;
    private final WalletUserRepository userRepository;
    private final AuditService auditService;
    private final EmailRateLimiter emailRateLimiter;

    public VerifyEmailWorkflow(OtpService otpService, AuthTokenService authTokenService,
                               WalletUserRepository userRepository, AuditService auditService,
                               EmailRateLimiter emailRateLimiter) {
        this.otpService = otpService;
        this.authTokenService = authTokenService;
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.emailRateLimiter = emailRateLimiter;
    }

    public Mono<AuthTokenPair> verifyEmail(String email, String code) {
        return emailRateLimiter.checkVerifyRate(email)
                .then(otpService.verify(email, code))
                .then(findOrCreateUser(email))
                .flatMap(user -> authTokenService.issueTokenPair(user, null)
                        .flatMap(tokenPair -> auditService.record("user", user.getId(),
                                        "USER_AUTHENTICATED", user.getId(), Map.of())
                                .thenReturn(tokenPair)));
    }

    private Mono<WalletUser> findOrCreateUser(String email) {
        return userRepository.findByEmail(email)
                .switchIfEmpty(Mono.defer(() -> {
                    var newUser = WalletUser.create(email);
                    return userRepository.save(newUser);
                }));
    }
}
