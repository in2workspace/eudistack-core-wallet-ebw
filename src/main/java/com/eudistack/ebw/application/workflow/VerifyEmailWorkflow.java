package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RegistrationTicketIssued;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.DuplicateAccountException;
import com.eudistack.ebw.domain.model.exception.InvalidOtpException;
import com.eudistack.ebw.domain.model.exception.OtpExpiredException;
import com.eudistack.ebw.domain.model.exception.TooManyAttemptsException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OtpService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.spi.EmailRateLimiter;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * Verifies the email code (FR-03) and creates the account and its Wallet Unit, or recognizes
 * the existing one (FR-04). Never opens a session (FR-16): it returns a registration ticket
 * that only allows registering a passkey or signing in with one of the account.
 */
@Service
public class VerifyEmailWorkflow {

    private final OtpService otpService;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final RegistrationTicketService ticketService;
    private final SecureRandomGenerator randomGenerator;
    private final AuditService auditService;
    private final EmailRateLimiter emailRateLimiter;

    @SuppressWarnings("java:S107")
    public VerifyEmailWorkflow(OtpService otpService, WalletUserRepository userRepository,
                               UserPasskeyRepository passkeyRepository, RegistrationTicketService ticketService,
                               SecureRandomGenerator randomGenerator, AuditService auditService,
                               EmailRateLimiter emailRateLimiter) {
        this.otpService = otpService;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.ticketService = ticketService;
        this.randomGenerator = randomGenerator;
        this.auditService = auditService;
        this.emailRateLimiter = emailRateLimiter;
    }

    public Mono<RegistrationTicketIssued> verifyEmail(String email, String code) {
        return emailRateLimiter.checkVerifyRate(email)
                .then(otpService.verify(email, code))
                .onErrorResume(VerifyEmailWorkflow::isCodeRejection,
                        e -> auditRejection(e).then(Mono.error(e)))
                .flatMap(verification -> auditService.record(AuthAuditEvents.ENTITY_EMAIL_VERIFICATION,
                                verification.getId(), AuthAuditEvents.EMAIL_CODE_VERIFIED, null, Map.of())
                        .then(findOrCreateUser(email)))
                .flatMap(user -> ticketService.issue(user.getId())
                        .flatMap(ticket -> passkeyRepository.countByUserId(user.getId())
                                .defaultIfEmpty(0L)
                                .map(count -> new RegistrationTicketIssued(ticket,
                                        RegistrationTicket.TTL.toSeconds(), count > 0))))
                .flatMap(result -> emailRateLimiter.resetForEmail(email).thenReturn(result));
    }

    private Mono<WalletUser> findOrCreateUser(String email) {
        return userRepository.findByEmail(email)
                .flatMap(existing -> auditService.record(AuthAuditEvents.ENTITY_USER, existing.getId(),
                                AuthAuditEvents.ACCOUNT_RECOGNIZED, existing.getId(), Map.of())
                        .thenReturn(existing))
                .switchIfEmpty(Mono.defer(() -> userRepository
                        .save(WalletUser.create(email, randomGenerator.generateBytes(WalletUser.USER_HANDLE_LENGTH)))
                        .flatMap(created -> auditService.record(AuthAuditEvents.ENTITY_USER, created.getId(),
                                        AuthAuditEvents.ACCOUNT_CREATED, created.getId(), Map.of())
                                .thenReturn(created))
                        // Two verifications of the same email at once: the second reuses the account.
                        .onErrorResume(DuplicateAccountException.class, e -> userRepository.findByEmail(email)
                                .switchIfEmpty(Mono.error(e)))));
    }

    private static boolean isCodeRejection(Throwable e) {
        return e instanceof InvalidOtpException || e instanceof OtpExpiredException
                || e instanceof TooManyAttemptsException;
    }

    /**
     * The rejected code has no account to refer to (it must not reveal whether the email has
     * one), so the event gets its own id and only the reason.
     */
    private Mono<Void> auditRejection(Throwable e) {
        String reason;
        if (e instanceof OtpExpiredException) {
            reason = "expired_code";
        } else if (e instanceof TooManyAttemptsException) {
            reason = "too_many_attempts";
        } else {
            reason = "invalid_code";
        }
        return auditService.record(AuthAuditEvents.ENTITY_EMAIL_VERIFICATION, UUID.randomUUID(),
                AuthAuditEvents.EMAIL_CODE_REJECTED, null, Map.of("reason", reason));
    }
}
