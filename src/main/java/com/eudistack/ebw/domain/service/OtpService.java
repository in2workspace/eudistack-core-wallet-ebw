package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

public class OtpService {

    private final EmailVerificationRepository verificationRepository;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final EmailSender emailSender;
    private final TenantConfigService tenantConfigService;
    private final String defaultMailFrom;
    private final int otpLength;
    private final Duration otpExpiration;
    private final int maxAttempts;

    public OtpService(EmailVerificationRepository verificationRepository,
                      HashProvider hashProvider,
                      SecureRandomGenerator randomGenerator,
                      EmailSender emailSender,
                      TenantConfigService tenantConfigService,
                      String defaultMailFrom,
                      int otpLength,
                      Duration otpExpiration,
                      int maxAttempts) {
        this.verificationRepository = verificationRepository;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.emailSender = emailSender;
        this.tenantConfigService = tenantConfigService;
        this.defaultMailFrom = defaultMailFrom;
        this.otpLength = otpLength;
        this.otpExpiration = otpExpiration;
        this.maxAttempts = maxAttempts;
    }

    public Mono<Void> generateAndSend(String email) {
        var code = randomGenerator.generateOtp(otpLength);
        return tenantConfigService.getStringOrDefault("ebw.mail_from", defaultMailFrom)
                .flatMap(from -> hashProvider.hash(code)
                        .flatMap(codeHash -> {
                            var verification = EmailVerification.create(
                                    email, codeHash, Instant.now().plus(otpExpiration));
                            return verificationRepository.invalidateByEmail(email)
                                    .then(verificationRepository.save(verification));
                        })
                        .then(emailSender.sendOtp(email, code, from)));
    }

    public Mono<EmailVerification> verify(String email, String code) {
        return verificationRepository.findActiveByEmail(email)
                .switchIfEmpty(Mono.error(new InvalidOtpException()))
                .flatMap(verification -> {
                    if (verification.isExpired()) {
                        return Mono.error(new OtpExpiredException());
                    }
                    if (verification.getAttempts() >= maxAttempts) {
                        return Mono.error(new TooManyAttemptsException());
                    }
                    return hashProvider.verify(code, verification.getCodeHash())
                            .flatMap(matches -> {
                                if (!matches) {
                                    verification.incrementAttempts();
                                    return verificationRepository.save(verification)
                                            .then(Mono.defer(() -> {
                                                if (verification.getAttempts() >= maxAttempts) {
                                                    return Mono.error(new TooManyAttemptsException());
                                                }
                                                return Mono.error(new InvalidOtpException());
                                            }));
                                }
                                verification.markUsed();
                                return verificationRepository.save(verification);
                            });
                });
    }
}
