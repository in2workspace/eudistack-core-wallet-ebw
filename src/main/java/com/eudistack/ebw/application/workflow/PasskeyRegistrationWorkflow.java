package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthRejectionReason;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.RegistrationOptions;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.DuplicateAccountException;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
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

/**
 * Registration ceremony of a new passkey with a registration ticket (FR-07, FR-08, FR-10).
 *
 * <p>The ceremony is consumed before verifying anything. With passkey custody in the tenant, a
 * passkey without PRF is rejected and nothing is stored. Consuming the ticket, storing the passkey
 * and opening the session are one transaction: a failure leaves nothing stored. Rejections are
 * audited outside it. If the account already had a passkey, the holder is emailed after the
 * commit; a failed or slow email never fails the registration.
 *
 * <p>With a registration ticket of an onboarding pre-registration (EUD-315, design §2.6), the same
 * transaction creates the account with the WebAuthn user handle the options already sent (decision
 * P2), or recognizes the account the ticket names if it still has no passkey; marks the passkey with
 * the pre-registration, deletes it and, for a new account, keeps the "it was not me" row without
 * token (decision P6). An onboarding ticket never adds a passkey to an account that has one: the
 * account is locked and checked inside the transaction (FR-28, decision P7). If the account of the
 * email appeared after the redemption, the passkey would carry another user handle and could never
 * sign in, so the registration is rejected too. Every registration ceremony is bound to the ticket
 * that started it (decision P9). All provisional, pending the Tech Lead.
 */
@Service
public class PasskeyRegistrationWorkflow {

    static final String DEFAULT_DISPLAY_NAME = "Passkey";
    static final Duration NOTICE_TIMEOUT = Duration.ofSeconds(5);

    private static final Logger log = LoggerFactory.getLogger(PasskeyRegistrationWorkflow.class);
    private static final String REJECTION_SUBJECT = "Passkey registration";

    private final RegistrationTicketService ticketService;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final WalletAuthSettingsService settingsService;
    private final PasskeyCustodyPolicy custodyPolicy;
    private final WebAuthnVerifier webAuthnVerifier;
    private final SecureRandomGenerator randomGenerator;
    private final SessionOpener sessionOpener;
    private final EmailSender emailSender;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;
    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final OnboardingDisavowalRepository disavowalRepository;
    private final NotifyOnboardingAccountCreatedWorkflow onboardingNotice;

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

    /** Account of an onboarding registration, and whether this registration created it. */
    private record OnboardingAccount(WalletUser user, boolean created) {}

    /** What an onboarding registration stored, for the new-account email after the commit. */
    private record OnboardingStored(IssuedSession session, UserPasskey passkey, boolean created) {}

    /** The onboarding ticket cannot register this passkey (decision P7); answered as {@code invalid_ticket}. */
    private static final class OnboardingAccountConflictException extends RuntimeException {
        private final String reason;

        private OnboardingAccountConflictException(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }
    }

    @SuppressWarnings("java:S107")
    public PasskeyRegistrationWorkflow(RegistrationTicketService ticketService, WalletUserRepository userRepository,
                                       UserPasskeyRepository passkeyRepository,
                                       WebAuthnCeremonyRepository ceremonyRepository,
                                       WalletAuthSettingsService settingsService, PasskeyCustodyPolicy custodyPolicy,
                                       WebAuthnVerifier webAuthnVerifier, SecureRandomGenerator randomGenerator,
                                       SessionOpener sessionOpener, EmailSender emailSender,
                                       AuditService auditService, TransactionRunner transactionRunner,
                                       OnboardingPreregistrationRepository preregistrationRepository,
                                       OnboardingDisavowalRepository disavowalRepository,
                                       NotifyOnboardingAccountCreatedWorkflow onboardingNotice) {
        this.ticketService = ticketService;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.ceremonyRepository = ceremonyRepository;
        this.settingsService = settingsService;
        this.custodyPolicy = custodyPolicy;
        this.webAuthnVerifier = webAuthnVerifier;
        this.randomGenerator = randomGenerator;
        this.sessionOpener = sessionOpener;
        this.emailSender = emailSender;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
        this.preregistrationRepository = preregistrationRepository;
        this.disavowalRepository = disavowalRepository;
        this.onboardingNotice = onboardingNotice;
    }

    public Mono<RegistrationOptions> startRegistration(String rawTicket) {
        return ticketService.resolve(rawTicket)
                .flatMap(ticket -> targetOf(ticket)
                        .flatMap(target -> Mono.zip(settingsService.relyingParty(), custodyPolicy.isPasskeyCustody(),
                                        passkeysOf(target.userId()))
                                .flatMap(tuple -> {
                                    var ceremony = WebAuthnCeremony.startRegistration(
                                            randomGenerator.generateBytes(WebAuthnCeremony.CHALLENGE_LENGTH),
                                            target.userId(), ticket.id());
                                    return ceremonyRepository.insert(ceremony)
                                            .thenReturn(new RegistrationOptions(ceremony.id(), tuple.getT1(),
                                                    target.userHandle(), target.email(), ceremony.challenge(),
                                                    tuple.getT3(), tuple.getT2()));
                                })));
    }

    /** The account of the ticket or, without one, the account its pre-registration will create. */
    private Mono<Target> targetOf(RegistrationTicket ticket) {
        if (ticket.userId() != null) {
            return accountOf(ticket).map(user -> new Target(user.getId(), user.getWebauthnUserHandle(),
                    user.getEmail()));
        }
        return preregistrationOf(ticket)
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
                        : registerWithOnboardingTicket(command, ticket));
    }

    private Mono<IssuedSession> registerForAccount(RegisterPasskeyCommand command, RegistrationTicket ticket) {
        return accountOf(ticket)
                .flatMap(user -> consumeCeremony(command.ceremonyId(), ticket)
                                .flatMap(ceremony -> Mono.zip(settingsService.relyingParty(),
                                                custodyPolicy.isPasskeyCustody())
                                        .flatMap(tuple -> registerVerified(command, ticket, ceremony, user,
                                                tuple.getT1(), tuple.getT2())))
                                .onErrorResume(RegistrationFailedException.class,
                                        e -> auditRejection(user, e.getReason()).then(Mono.error(e))));
    }

    private Mono<IssuedSession> registerWithOnboardingTicket(RegisterPasskeyCommand command,
                                                             RegistrationTicket ticket) {
        return preregistrationOf(ticket)
                .flatMap(preregistration -> consumeCeremony(command.ceremonyId(), ticket)
                        .flatMap(ceremony -> Mono.zip(settingsService.relyingParty(), custodyPolicy.isPasskeyCustody())
                                .flatMap(tuple -> registerOnboarding(command, ticket, preregistration, ceremony,
                                        tuple.getT1(), tuple.getT2())))
                        .onErrorResume(RegistrationFailedException.class,
                                e -> auditOnboardingRejection(preregistration, e.getReason().code())
                                        .then(Mono.error(e))));
    }

    @SuppressWarnings("java:S107")
    private Mono<IssuedSession> registerOnboarding(RegisterPasskeyCommand command, RegistrationTicket ticket,
                                                   OnboardingPreregistration preregistration,
                                                   WebAuthnCeremony ceremony, RelyingPartySettings relyingParty,
                                                   boolean passkeyCustody) {
        boolean prfSupported = Boolean.TRUE.equals(command.prfSupported());
        if (passkeyCustody && !prfSupported) {
            AuthRejectionLog.log(log, REJECTION_SUBJECT, AuthRejectionReason.PRF_UNSUPPORTED);
            return auditOnboardingRejection(preregistration, AuthRejectionReason.PRF_UNSUPPORTED.code())
                    .then(Mono.error(new PasskeyPrfUnsupportedException()));
        }
        return verify(command.credentialJson(), ceremony, relyingParty)
                .flatMap(verified -> passkeyRepository.findByCredentialId(verified.credentialId())
                        .flatMap(existing -> Mono.<VerifiedPasskeyRegistration>error(new RegistrationFailedException(
                                AuthRejectionReason.CREDENTIAL_ALREADY_REGISTERED)))
                        .defaultIfEmpty(verified))
                .flatMap(verified -> transactionRunner.inTransaction(
                        ticketService.consume(ticket)
                                .then(onboardingAccount(ticket, preregistration))
                                .flatMap(account -> storeOnboardingPasskey(command, account, verified, prfSupported,
                                        preregistration))))
                .doOnError(RegistrationFailedException.class,
                        e -> AuthRejectionLog.log(log, REJECTION_SUBJECT, e.getReason()))
                // PROVISIONAL (decision P5): the new-account email goes after the commit, until the device
                // registration of EUD-15 sends it. Best effort: it never fails the registration.
                .flatMap(stored -> stored.created()
                        ? onboardingNotice.notify(stored.passkey().getId(), stored.passkey().getDisplayName())
                                .thenReturn(stored.session())
                        : Mono.just(stored.session()))
                .onErrorResume(OnboardingAccountConflictException.class,
                        e -> preregistrationRepository.deleteById(preregistration.id())
                                .then(auditOnboardingRejection(preregistration, e.reason))
                                .then(Mono.error(new InvalidTicketException())));
    }

    /** Inside the transaction: passkey, mark, session, pre-registration deleted, "it was not me" row. */
    private Mono<OnboardingStored> storeOnboardingPasskey(RegisterPasskeyCommand command, OnboardingAccount account,
                                                       VerifiedPasskeyRegistration verified, boolean prfSupported,
                                                       OnboardingPreregistration preregistration) {
        return storePasskey(command, account.user(), verified, prfSupported)
                .flatMap(passkey -> passkeyRepository.markOnboarding(passkey.getId(), preregistration.id())
                        .then(sessionOpener.open(account.user(), passkey.getId(), command.replacedRefreshToken(),
                                "registration"))
                        .flatMap(session -> preregistrationRepository.deleteById(preregistration.id())
                                .then(account.created()
                                        ? disavowalRepository.insert(OnboardingDisavowal.pending(
                                                account.user().getId(), passkey.getId(),
                                                preregistration.requestedBy(), passkey.getCreatedAt())).then()
                                        : Mono.<Void>empty())
                                .thenReturn(new OnboardingStored(session, passkey, account.created()))));
    }

    /**
     * Inside the registration transaction. The account the ticket names is locked, so a concurrent
     * registration of the same account waits and then finds the passkey of the first one.
     */
    private Mono<OnboardingAccount> onboardingAccount(RegistrationTicket ticket,
                                                      OnboardingPreregistration preregistration) {
        if (ticket.userId() != null) {
            return userRepository.lockById(ticket.userId())
                    .switchIfEmpty(Mono.error(new InvalidTicketException()))
                    .flatMap(user -> passkeyRepository.countByUserId(user.getId()).defaultIfEmpty(0L)
                            .flatMap(passkeys -> passkeys > 0
                                    ? Mono.<OnboardingAccount>error(
                                            new OnboardingAccountConflictException("account_has_passkeys"))
                                    : auditService.record(AuthAuditEvents.ENTITY_USER, user.getId(),
                                                    AuthAuditEvents.ACCOUNT_RECOGNIZED, user.getId(), Map.of())
                                            .thenReturn(new OnboardingAccount(user, false))));
        }
        return userRepository.findByEmail(preregistration.email())
                .flatMap(existing -> Mono.<OnboardingAccount>error(
                        new OnboardingAccountConflictException("account_appeared")))
                .switchIfEmpty(Mono.defer(() -> userRepository
                        .save(WalletUser.create(preregistration.email(), preregistration.webauthnUserHandle()))
                        .onErrorMap(DuplicateAccountException.class,
                                e -> new OnboardingAccountConflictException("account_appeared"))
                        .flatMap(created -> auditService.record(AuthAuditEvents.ENTITY_USER, created.getId(),
                                        AuthAuditEvents.ACCOUNT_CREATED, created.getId(), Map.of("onboarding", true))
                                .thenReturn(new OnboardingAccount(created, true)))));
    }

    /** The pre-registration of the ticket; without an account it must hold the user handle (decision P2). */
    private Mono<OnboardingPreregistration> preregistrationOf(RegistrationTicket ticket) {
        if (ticket.preregistrationId() == null) {
            return Mono.error(new InvalidTicketException());
        }
        return preregistrationRepository.findById(ticket.preregistrationId())
                .filter(preregistration -> preregistration.webauthnUserHandle() != null || ticket.userId() != null)
                .switchIfEmpty(Mono.error(new InvalidTicketException()));
    }

    private Mono<Void> auditOnboardingRejection(OnboardingPreregistration preregistration, String reason) {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, preregistration.id(),
                AuthAuditEvents.PASSKEY_REJECTED, null, Map.of("reason", reason));
    }

    private Mono<IssuedSession> registerVerified(RegisterPasskeyCommand command, RegistrationTicket ticket,
                                                 WebAuthnCeremony ceremony, WalletUser user,
                                                 RelyingPartySettings relyingParty, boolean passkeyCustody) {
        // Declared by the Wallet App after its own PRF check, not verified here: the PRF extension
        // outputs are not signed by the authenticator, and Safari only reports PRF on get(), never on
        // create(). A passkey without PRF stored as prf-enabled cannot unwrap the holder key, so
        // signing fails for it; it never gives access to keys it could not derive.
        boolean prfSupported = Boolean.TRUE.equals(command.prfSupported());
        if (passkeyCustody && !prfSupported) {
            AuthRejectionLog.log(log, REJECTION_SUBJECT, AuthRejectionReason.PRF_UNSUPPORTED);
            return auditRejection(user, AuthRejectionReason.PRF_UNSUPPORTED)
                    .then(Mono.error(new PasskeyPrfUnsupportedException()));
        }
        return verify(command.credentialJson(), ceremony, relyingParty)
                .flatMap(verified -> passkeyRepository.findByCredentialId(verified.credentialId())
                        .flatMap(existing -> Mono.<VerifiedPasskeyRegistration>error(new RegistrationFailedException(
                                AuthRejectionReason.CREDENTIAL_ALREADY_REGISTERED)))
                        .defaultIfEmpty(verified))
                .flatMap(verified -> transactionRunner.inTransaction(
                        ticketService.consume(ticket)
                                .then(passkeyRepository.countByUserId(user.getId()).defaultIfEmpty(0L))
                                .flatMap(previousPasskeys -> storePasskey(command, user, verified, prfSupported)
                                        .flatMap(passkey -> sessionOpener.open(user, passkey.getId(),
                                                        command.replacedRefreshToken(), "registration")
                                                .map(session -> new Stored(session, passkey, previousPasskeys > 0))))))
                .doOnError(RegistrationFailedException.class,
                        e -> AuthRejectionLog.log(log, REJECTION_SUBJECT, e.getReason()))
                .flatMap(stored -> stored.hadPasskeys()
                        ? notifyNewPasskey(user, stored.passkey()).thenReturn(stored.session())
                        : Mono.just(stored.session()));
    }

    private Mono<VerifiedPasskeyRegistration> verify(String credentialJson, WebAuthnCeremony ceremony,
                                                     RelyingPartySettings relyingParty) {
        return Mono.fromCallable(() -> webAuthnVerifier.verifyRegistration(credentialJson, ceremony.challenge(),
                        relyingParty))
                .onErrorMap(WebAuthnVerificationException.class, e -> {
                    AuthRejectionLog.detail(log, REJECTION_SUBJECT, e);
                    return new RegistrationFailedException(AuthRejectionReason.VERIFICATION_FAILED);
                });
    }

    private Mono<UserPasskey> storePasskey(RegisterPasskeyCommand command, WalletUser user,
                                           VerifiedPasskeyRegistration verified, boolean prfSupported) {
        var displayName = command.displayName() == null || command.displayName().isBlank()
                ? DEFAULT_DISPLAY_NAME : command.displayName().trim();
        var passkey = UserPasskey.register(user.getId(), verified, prfSupported, displayName, command.userAgent());
        return passkeyRepository.insert(passkey)
                .flatMap(saved -> auditService.record(AuthAuditEvents.ENTITY_PASSKEY, saved.getId(),
                                AuthAuditEvents.PASSKEY_REGISTERED, user.getId(),
                                Map.of("prf_enabled", saved.isPrfEnabled()))
                        .thenReturn(saved));
    }

    private Mono<WebAuthnCeremony> consumeCeremony(UUID ceremonyId, RegistrationTicket ticket) {
        if (ceremonyId == null) {
            return Mono.error(new RegistrationFailedException(AuthRejectionReason.CEREMONY_MISSING));
        }
        return ceremonyRepository.consume(ceremonyId, CeremonyType.REGISTRATION)
                .switchIfEmpty(Mono.error(new RegistrationFailedException(AuthRejectionReason.CEREMONY_INVALID)))
                .flatMap(ceremony -> Objects.equals(ceremony.userId(), ticket.userId())
                        && Objects.equals(ceremony.registrationTicketId(), ticket.id())
                        ? Mono.just(ceremony)
                        : Mono.error(new RegistrationFailedException(AuthRejectionReason.CEREMONY_MISMATCH)));
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
