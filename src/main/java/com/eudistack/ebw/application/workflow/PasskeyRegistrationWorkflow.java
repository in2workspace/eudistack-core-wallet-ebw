package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthRejectionReason;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.RegistrationOptions;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static com.eudistack.ebw.application.workflow.PasskeyRegistrationSteps.REJECTION_SUBJECT;

/**
 * Registration ceremony of a new passkey with a registration ticket (FR-07, FR-08, FR-10).
 *
 * <p>The ceremony is consumed before verifying anything. With passkey custody in the tenant, a
 * passkey without PRF is rejected and nothing is stored. Consuming the ticket, storing the passkey
 * and opening the session are one transaction: a failure leaves nothing stored. Rejections are
 * audited outside it. If the account already had a passkey, the holder is emailed after the
 * commit; a failed or slow email never fails the registration.
 *
 * <p>A registration ticket of an onboarding pre-registration (EUD-315, design §2.6) is registered by
 * {@link RegisterOnboardingPasskeyWorkflow}. Its options carry the email and the WebAuthn user handle of
 * the pre-registration when the account does not exist yet (decision P2).
 */
@Service
public class PasskeyRegistrationWorkflow {

    static final Duration NOTICE_TIMEOUT = Duration.ofSeconds(5);

    private static final Logger log = LoggerFactory.getLogger(PasskeyRegistrationWorkflow.class);

    private final RegistrationTicketService ticketService;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final SecureRandomGenerator randomGenerator;
    private final SessionOpener sessionOpener;
    private final EmailSender emailSender;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;
    private final PasskeyRegistrationSteps steps;
    private final RegisterOnboardingPasskeyWorkflow onboardingRegistration;

    /** Input of {@link #register}. {@code replacedRefreshToken} is the refresh cookie of the request, if any. */
    public record RegisterPasskeyCommand(String rawTicket, UUID ceremonyId, String credentialJson,
                                         Boolean prfSupported, String displayName, String userAgent,
                                         String replacedRefreshToken) {}

    private record Stored(IssuedSession session, UserPasskey passkey, boolean hadPasskeys) {}

    /** Who the passkey is for: the account, or the one an onboarding pre-registration will create. */
    private record Target(UUID userId, byte[] userHandle, String email) {

        @Override
        public boolean equals(Object other) {
            return other instanceof Target(var otherUserId, var otherHandle, var otherEmail)
                    && Objects.equals(userId, otherUserId)
                    && Arrays.equals(userHandle, otherHandle)
                    && Objects.equals(email, otherEmail);
        }

        @Override
        public int hashCode() {
            return 31 * Objects.hash(userId, email) + Arrays.hashCode(userHandle);
        }

        /** Never prints the email: it is personal data. */
        @Override
        public String toString() {
            return "Target[userId=" + userId + ", email=[redacted]]";
        }
    }

    @SuppressWarnings("java:S107")
    public PasskeyRegistrationWorkflow(RegistrationTicketService ticketService, WalletUserRepository userRepository,
                                       UserPasskeyRepository passkeyRepository,
                                       WebAuthnCeremonyRepository ceremonyRepository,
                                       SecureRandomGenerator randomGenerator, SessionOpener sessionOpener,
                                       EmailSender emailSender, AuditService auditService,
                                       TransactionRunner transactionRunner, PasskeyRegistrationSteps steps,
                                       RegisterOnboardingPasskeyWorkflow onboardingRegistration) {
        this.ticketService = ticketService;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.ceremonyRepository = ceremonyRepository;
        this.randomGenerator = randomGenerator;
        this.sessionOpener = sessionOpener;
        this.emailSender = emailSender;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
        this.steps = steps;
        this.onboardingRegistration = onboardingRegistration;
    }

    public Mono<RegistrationOptions> startRegistration(String rawTicket) {
        return ticketService.resolve(rawTicket)
                .flatMap(ticket -> targetOf(ticket)
                        .flatMap(target -> Mono.zip(steps.settings(), passkeysOf(target.userId()))
                                .flatMap(tuple -> {
                                    var settings = tuple.getT1();
                                    var ceremony = WebAuthnCeremony.startRegistration(
                                            randomGenerator.generateBytes(WebAuthnCeremony.CHALLENGE_LENGTH),
                                            target.userId(), ticket.id());
                                    return ceremonyRepository.insert(ceremony)
                                            .thenReturn(new RegistrationOptions(ceremony.id(),
                                                    settings.relyingParty(), target.userHandle(), target.email(),
                                                    ceremony.challenge(), tuple.getT2(), settings.passkeyCustody()));
                                })));
    }

    /** The account of the ticket or, without one, the account its pre-registration will create. */
    private Mono<Target> targetOf(RegistrationTicket ticket) {
        if (ticket.userId() != null) {
            return accountOf(ticket).map(user -> new Target(user.getId(), user.getWebauthnUserHandle(),
                    user.getEmail()));
        }
        return onboardingRegistration.preregistrationOf(ticket)
                .map(preregistration -> new Target(null, preregistration.webauthnUserHandle(),
                        preregistration.email()));
    }

    private Mono<List<UserPasskey>> passkeysOf(UUID userId) {
        return userId == null ? Mono.just(List.of()) : passkeyRepository.findByUserId(userId).collectList();
    }

    public Mono<IssuedSession> register(RegisterPasskeyCommand command) {
        return ticketService.resolve(command.rawTicket())
                .flatMap(ticket -> ticket.preregistrationId() == null
                        ? registerForAccount(command, ticket)
                        : onboardingRegistration.register(command, ticket));
    }

    private Mono<IssuedSession> registerForAccount(RegisterPasskeyCommand command, RegistrationTicket ticket) {
        return accountOf(ticket)
                .flatMap(user -> steps.consumeCeremony(command.ceremonyId(), ticket)
                                .flatMap(ceremony -> steps.settings()
                                        .flatMap(settings -> registerVerified(command, ticket, ceremony, user,
                                                settings)))
                                .onErrorResume(RegistrationFailedException.class,
                                        e -> auditRejection(user, e.getReason()).then(Mono.error(e))));
    }

    private Mono<IssuedSession> registerVerified(RegisterPasskeyCommand command, RegistrationTicket ticket,
                                                 WebAuthnCeremony ceremony, WalletUser user,
                                                 PasskeyRegistrationSteps.Settings settings) {
        // Declared by the Wallet App after its own PRF check, not verified here: the PRF extension
        // outputs are not signed by the authenticator, and Safari only reports PRF on get(), never on
        // create(). A passkey without PRF stored as prf-enabled cannot unwrap the holder key, so
        // signing fails for it; it never gives access to keys it could not derive.
        boolean prfSupported = Boolean.TRUE.equals(command.prfSupported());
        if (settings.passkeyCustody() && !prfSupported) {
            AuthRejectionLog.log(log, REJECTION_SUBJECT, AuthRejectionReason.PRF_UNSUPPORTED);
            return auditRejection(user, AuthRejectionReason.PRF_UNSUPPORTED)
                    .then(Mono.error(new PasskeyPrfUnsupportedException()));
        }
        return steps.verifyNew(command.credentialJson(), ceremony, settings.relyingParty(), log)
                .flatMap(verified -> transactionRunner.inTransaction(
                        ticketService.consume(ticket)
                                .then(passkeyRepository.countByUserId(user.getId()).defaultIfEmpty(0L))
                                .flatMap(previousPasskeys -> steps.storePasskey(command, user, verified, prfSupported)
                                        .flatMap(passkey -> sessionOpener.open(user, passkey.getId(),
                                                        command.replacedRefreshToken(), "registration")
                                                .map(session -> new Stored(session, passkey, previousPasskeys > 0))))))
                .doOnError(RegistrationFailedException.class,
                        e -> AuthRejectionLog.log(log, REJECTION_SUBJECT, e.getReason()))
                .flatMap(stored -> stored.hadPasskeys()
                        ? notifyNewPasskey(user, stored.passkey()).thenReturn(stored.session())
                        : Mono.just(stored.session()));
    }

    /** A ticket without account and without pre-registration never creates one (EC-07). */
    private Mono<WalletUser> accountOf(RegistrationTicket ticket) {
        if (ticket.userId() == null) {
            return Mono.error(new InvalidTicketException());
        }
        return userRepository.findById(ticket.userId())
                .switchIfEmpty(Mono.error(new InvalidTicketException()));
    }

    private Mono<Void> auditRejection(WalletUser user, AuthRejectionReason reason) {
        return auditService.record(AuthAuditEvents.ENTITY_USER, user.getId(), AuthAuditEvents.PASSKEY_REJECTED,
                user.getId(), Map.of("reason", reason.code()));
    }

    /** FR-10: best-effort and bounded. A failed or slow email is audited and never fails the registration. */
    private Mono<Void> notifyNewPasskey(WalletUser user, UserPasskey passkey) {
        return emailSender.sendNewPasskeyNotice(user.getEmail())
                .timeout(NOTICE_TIMEOUT)
                .then(auditService.record(AuthAuditEvents.ENTITY_PASSKEY, passkey.getId(),
                        AuthAuditEvents.NEW_PASSKEY_NOTICE_SENT, user.getId(), Map.of()))
                .onErrorResume(e -> {
                    log.warn("Could not send the new passkey notice for passkey {}: {}", passkey.getId(),
                            e.getClass().getName());
                    return auditService.record(AuthAuditEvents.ENTITY_PASSKEY, passkey.getId(),
                                    AuthAuditEvents.NEW_PASSKEY_NOTICE_FAILED, user.getId(), Map.of())
                            .onErrorResume(auditError -> Mono.empty());
                });
    }
}
