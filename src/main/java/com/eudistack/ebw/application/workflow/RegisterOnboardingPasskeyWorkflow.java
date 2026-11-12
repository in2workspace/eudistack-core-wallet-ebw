package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow.RegisterPasskeyCommand;
import com.eudistack.ebw.domain.model.AuthRejectionReason;
import com.eudistack.ebw.domain.model.DeviceLabel;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.DuplicateAccountException;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;

import static com.eudistack.ebw.application.workflow.PasskeyRegistrationSteps.REJECTION_SUBJECT;

/**
 * Registration of a passkey with a registration ticket of an onboarding pre-registration (EUD-315,
 * design §2.6). {@link PasskeyRegistrationWorkflow#register} delegates here when the ticket names a
 * pre-registration.
 *
 * <p>The same transaction consumes the ticket and creates the account with the WebAuthn user handle the
 * options already sent (decision P2), or recognizes the account the ticket names if it still has no
 * passkey; marks the passkey with the pre-registration, deletes it and keeps the "it was not me" row
 * without token (decision P6), for a new account and for one that already existed (decision P17). An
 * onboarding ticket never adds a passkey to an account that has one: the account is locked and checked
 * inside the transaction (FR-28, decision P7). If the account of the email appeared after the redemption,
 * the passkey would carry another user handle and could never sign in, so the registration is rejected
 * too. Every registration ceremony is bound to the ticket that started it (decision P9). All provisional,
 * pending the Tech Lead.
 */
@Service
public class RegisterOnboardingPasskeyWorkflow {

    private static final Logger log = LoggerFactory.getLogger(RegisterOnboardingPasskeyWorkflow.class);

    private final RegistrationTicketService ticketService;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final SessionOpener sessionOpener;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;
    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final OnboardingDisavowalRepository disavowalRepository;
    private final NotifyOnboardingAccountCreatedWorkflow onboardingNotice;
    private final PasskeyRegistrationSteps steps;

    /** Account of an onboarding registration, and whether this registration created it. */
    private record OnboardingAccount(WalletUser user, boolean created) {}

    /** What an onboarding registration stored, for the email after the commit. */
    private record OnboardingStored(IssuedSession session, UserPasskey passkey) {}

    /** The onboarding ticket cannot register this passkey (decision P7); answered as {@code invalid_ticket}. */
    private static final class OnboardingAccountConflictException extends RuntimeException {
        private final String reason;

        private OnboardingAccountConflictException(String reason) {
            super(reason, null, false, false);
            this.reason = reason;
        }
    }

    @SuppressWarnings("java:S107")
    RegisterOnboardingPasskeyWorkflow(RegistrationTicketService ticketService, WalletUserRepository userRepository,
                                      UserPasskeyRepository passkeyRepository, SessionOpener sessionOpener,
                                      AuditService auditService, TransactionRunner transactionRunner,
                                      OnboardingPreregistrationRepository preregistrationRepository,
                                      OnboardingDisavowalRepository disavowalRepository,
                                      NotifyOnboardingAccountCreatedWorkflow onboardingNotice,
                                      PasskeyRegistrationSteps steps) {
        this.ticketService = ticketService;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.sessionOpener = sessionOpener;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
        this.preregistrationRepository = preregistrationRepository;
        this.disavowalRepository = disavowalRepository;
        this.onboardingNotice = onboardingNotice;
        this.steps = steps;
    }

    /** Registers the passkey of a resolved ticket that names a pre-registration. */
    Mono<IssuedSession> register(RegisterPasskeyCommand command, RegistrationTicket ticket) {
        return preregistrationOf(ticket)
                .flatMap(preregistration -> steps.consumeCeremony(command.ceremonyId(), ticket)
                        .flatMap(ceremony -> steps.settings()
                                .flatMap(settings -> register(command, ticket, preregistration, ceremony, settings)))
                        .onErrorResume(RegistrationFailedException.class,
                                e -> auditRejection(preregistration, e.getReason().code())
                                        .then(Mono.error(e))));
    }

    /** The pre-registration of the ticket; without an account it must hold the user handle (decision P2). */
    Mono<OnboardingPreregistration> preregistrationOf(RegistrationTicket ticket) {
        if (ticket.preregistrationId() == null) {
            return Mono.error(new InvalidTicketException());
        }
        return preregistrationRepository.findById(ticket.preregistrationId())
                .filter(preregistration -> preregistration.webauthnUserHandle() != null || ticket.userId() != null)
                .switchIfEmpty(Mono.error(new InvalidTicketException()));
    }

    private Mono<IssuedSession> register(RegisterPasskeyCommand command, RegistrationTicket ticket,
                                         OnboardingPreregistration preregistration, WebAuthnCeremony ceremony,
                                         PasskeyRegistrationSteps.Settings settings) {
        boolean prfSupported = Boolean.TRUE.equals(command.prfSupported());
        if (settings.passkeyCustody() && !prfSupported) {
            AuthRejectionLog.log(log, REJECTION_SUBJECT, AuthRejectionReason.PRF_UNSUPPORTED);
            return auditRejection(preregistration, AuthRejectionReason.PRF_UNSUPPORTED.code())
                    .then(Mono.error(new PasskeyPrfUnsupportedException()));
        }
        return steps.verifyNew(command.credentialJson(), ceremony, settings.relyingParty(), log)
                .flatMap(verified -> transactionRunner.inTransaction(
                        ticketService.consume(ticket)
                                .then(onboardingAccount(ticket, preregistration))
                                .flatMap(account -> storePasskey(command, account, verified, prfSupported,
                                        preregistration))))
                .doOnError(RegistrationFailedException.class,
                        e -> AuthRejectionLog.log(log, REJECTION_SUBJECT, e.getReason()))
                // PROVISIONAL (decision P5): the email goes after the commit, until the device
                // registration of EUD-15 sends it. Best effort: it never fails the registration.
                // The device is the label the service derives from the User-Agent, never the name the client
                // sends (decision P19): that text is free and would reach an email with the tenant's brand.
                .flatMap(stored -> onboardingNotice.notify(stored.passkey().getId(),
                                DeviceLabel.of(command.userAgent()).value())
                        .thenReturn(stored.session()))
                .onErrorResume(OnboardingAccountConflictException.class,
                        e -> preregistrationRepository.deleteById(preregistration.id())
                                .then(auditRejection(preregistration, e.reason))
                                .then(Mono.error(new InvalidTicketException())));
    }

    /** Inside the transaction: passkey, mark, session, pre-registration deleted, "it was not me" row (EC-01, P17). */
    private Mono<OnboardingStored> storePasskey(RegisterPasskeyCommand command, OnboardingAccount account,
                                                VerifiedPasskeyRegistration verified, boolean prfSupported,
                                                OnboardingPreregistration preregistration) {
        return steps.storePasskey(command, account.user(), verified, prfSupported)
                .flatMap(passkey -> passkeyRepository.markOnboarding(passkey.getId(), preregistration.id())
                        .then(sessionOpener.open(account.user(), passkey.getId(), command.replacedRefreshToken(),
                                "registration"))
                        .flatMap(session -> preregistrationRepository.deleteById(preregistration.id())
                                .then(disavowalRepository.insert(OnboardingDisavowal.pending(
                                        account.user().getId(), passkey.getId(), preregistration.requestedBy(),
                                        passkey.getCreatedAt(), account.created())))
                                .thenReturn(new OnboardingStored(session, passkey))));
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
        // Ignoring the case of the email (decision P16): one account or several, the ticket does not create another.
        // wallet_user.email is unique only exactly, so two registrations of "Ana@x" and "ana@x" could both find
        // nothing and both insert: the advisory lock serializes them and the second finds the first (F1-n of the
        // security audit). It becomes redundant once a unique index on lower(email) exists (issue P16, tasks.md).
        return userRepository.lockEmailIgnoreCase(preregistration.email())
                .thenMany(userRepository.findAllByEmailIgnoreCase(preregistration.email()))
                .next()
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

    private Mono<Void> auditRejection(OnboardingPreregistration preregistration, String reason) {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, preregistration.id(),
                AuthAuditEvents.PASSKEY_REJECTED, null, Map.of("reason", reason));
    }
}
