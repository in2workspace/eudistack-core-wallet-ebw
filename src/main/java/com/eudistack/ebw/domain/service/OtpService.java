package com.eudistack.ebw.domain.service;

import com.eudistack.ebw.domain.model.EmailVerification;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.repository.EmailVerificationRepository;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Email one-time codes (EUD-8 FR-03): 6 digits, valid 10 minutes, 5 attempts, a new code
 * invalidates the previous one. Attempts and consumption are single conditional updates, so
 * concurrent verifications cannot exceed the attempts nor use a code twice.
 */
@RequiredArgsConstructor
public class OtpService {

    private final EmailVerificationRepository verificationRepository;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final EmailSender emailSender;
    private final int otpLength;
    private final Duration otpExpiration;
    private final int maxAttempts;

    /**
     * Generates a new code for the email (invalidating the previous one) and sends it.
     * Emits the id of the verification, so it can be audited without the email.
     */
    public Mono<UUID> generateAndSend(String email) {
        var code = randomGenerator.generateOtp(otpLength);
        return hashProvider.hash(code)
                .flatMap(codeHash -> {
                    var verification = EmailVerification.create(
                            email, codeHash, Instant.now().plus(otpExpiration));
                    return verificationRepository.invalidateByEmail(email)
                            .then(verificationRepository.save(verification));
                })
                .flatMap(saved -> emailSender.sendOtp(email, code).thenReturn(saved.getId()));
    }

    /**
     * Verifies the code against the current one. A code replaced by a newer one is answered as
     * expired, like an expired code (contract {@code expired_code}).
     */
    public Mono<EmailVerification> verify(String email, String code) {
        return verificationRepository.findLatestUnusedByEmail(email)
                .switchIfEmpty(Mono.error(new InvalidOtpException()))
                .flatMap(verification -> {
                    if (verification.isExpired()) {
                        return Mono.error(new OtpExpiredException());
                    }
                    if (verification.getAttempts() >= maxAttempts) {
                        return Mono.error(new TooManyAttemptsException());
                    }
                    return hashProvider.verify(code, verification.getCodeHash())
                            .flatMap(matches -> Boolean.TRUE.equals(matches)
                                    ? consume(verification)
                                    : reject(email, code, verification));
                });
    }

    private Mono<EmailVerification> consume(EmailVerification verification) {
        return verificationRepository.markUsedIfUsable(verification.getId(), maxAttempts)
                .flatMap(consumed -> {
                    if (!Boolean.TRUE.equals(consumed)) {
                        // Used or out of attempts in a concurrent request.
                        return Mono.error(new InvalidOtpException());
                    }
                    verification.markUsed();
                    return Mono.just(verification);
                });
    }

    private Mono<EmailVerification> reject(String email, String code, EmailVerification current) {
        return verificationRepository.incrementAttempts(current.getId())
                .flatMap(attempts -> {
                    if (attempts >= maxAttempts) {
                        return Mono.error(new TooManyAttemptsException());
                    }
                    return matchesReplacedCode(email, code)
                            .flatMap(replaced -> Mono.<EmailVerification>error(Boolean.TRUE.equals(replaced)
                                    ? new OtpExpiredException()
                                    : new InvalidOtpException()));
                });
    }

    private Mono<Boolean> matchesReplacedCode(String email, String code) {
        Flux<EmailVerification> replaced = verificationRepository
                .findReplacedSince(email, Instant.now().minus(otpExpiration));
        return replaced.concatMap(previous -> hashProvider.verify(code, previous.getCodeHash()))
                .any(Boolean.TRUE::equals);
    }
}
