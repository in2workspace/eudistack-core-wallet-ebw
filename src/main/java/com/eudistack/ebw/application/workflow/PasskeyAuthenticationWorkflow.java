package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AuthRejectionReason;
import com.eudistack.ebw.domain.model.AuthenticationOptions;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.PasskeyAssertion;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.AuthenticationFailedException;
import com.eudistack.ebw.domain.model.exception.UnknownCredentialException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Sign-in with a passkey (FR-12 to FR-17): discoverable credentials without a ticket, or the
 * passkeys of the ticket's account after an email code (FR-09).
 *
 * <p>The client gets {@code unknown_credential} when the tenant has no passkey with the
 * credential id, and {@code authentication_failed} for any other failure. The fixed reason goes
 * to the log and the audit trail.
 */
@Service
public class PasskeyAuthenticationWorkflow {

    private static final Logger log = LoggerFactory.getLogger(PasskeyAuthenticationWorkflow.class);
    private static final String WHAT = "Passkey authentication";

    private final RegistrationTicketService ticketService;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final WalletAuthSettingsService settingsService;
    private final WebAuthnVerifier webAuthnVerifier;
    private final SecureRandomGenerator randomGenerator;
    private final SessionOpener sessionOpener;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;

    /** Input of {@link #openSession}. {@code rawTicket} and {@code replacedRefreshToken} are optional. */
    public record OpenSessionCommand(String rawTicket, UUID ceremonyId, String credentialJson,
                                     String replacedRefreshToken) {}

    @SuppressWarnings("java:S107")
    public PasskeyAuthenticationWorkflow(RegistrationTicketService ticketService, WalletUserRepository userRepository,
                                         UserPasskeyRepository passkeyRepository,
                                         WebAuthnCeremonyRepository ceremonyRepository,
                                         WalletAuthSettingsService settingsService, WebAuthnVerifier webAuthnVerifier,
                                         SecureRandomGenerator randomGenerator, SessionOpener sessionOpener,
                                         AuditService auditService, TransactionRunner transactionRunner) {
        this.ticketService = ticketService;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.ceremonyRepository = ceremonyRepository;
        this.settingsService = settingsService;
        this.webAuthnVerifier = webAuthnVerifier;
        this.randomGenerator = randomGenerator;
        this.sessionOpener = sessionOpener;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
    }

    public Mono<AuthenticationOptions> startAuthentication(String rawTicket) {
        return resolveOptionalTicket(rawTicket)
                .flatMap(ticket -> Mono.zip(settingsService.relyingParty(), allowCredentials(ticket))
                        .flatMap(tuple -> {
                            var ceremony = WebAuthnCeremony.start(CeremonyType.AUTHENTICATION,
                                    randomGenerator.generateBytes(WebAuthnCeremony.CHALLENGE_LENGTH),
                                    ticket.map(RegistrationTicket::userId).orElse(null));
                            return ceremonyRepository.insert(ceremony)
                                    .thenReturn(new AuthenticationOptions(ceremony.id(), tuple.getT1().rpId(),
                                            ceremony.challenge(), tuple.getT2()));
                        }));
    }

    public Mono<IssuedSession> openSession(OpenSessionCommand command) {
        var passkeyRef = new AtomicReference<UserPasskey>();
        return resolveOptionalTicket(command.rawTicket())
                .flatMap(ticket -> consumeCeremony(command.ceremonyId(), ticket)
                        .flatMap(ceremony -> readAssertion(command.credentialJson())
                                .flatMap(assertion -> findPasskey(assertion)
                                        .doOnNext(passkeyRef::set)
                                        .flatMap(passkey -> accountOf(passkey, ticket, assertion)
                                                .flatMap(user -> verify(command, ceremony, passkey)
                                                        // As in the registration: the ticket is used up only
                                                        // if the session opens.
                                                        .then(Mono.defer(() -> transactionRunner.inTransaction(
                                                                consumeTicket(ticket).then(sessionOpener.open(user,
                                                                        passkey.getId(), command.replacedRefreshToken(),
                                                                        ticket.isPresent() ? "passkey_with_ticket"
                                                                                : "passkey"))))))))))
                .onErrorResume(e -> e instanceof AuthenticationFailedException
                                || e instanceof UnknownCredentialException,
                        e -> auditRejection(command.ceremonyId(), passkeyRef.get(), e).then(Mono.error(e)));
    }

    private Mono<Optional<RegistrationTicket>> resolveOptionalTicket(String rawTicket) {
        if (rawTicket == null) {
            return Mono.just(Optional.empty());
        }
        return ticketService.resolve(rawTicket).map(Optional::of);
    }

    private Mono<List<UserPasskey>> allowCredentials(Optional<RegistrationTicket> ticket) {
        return ticket.map(t -> passkeyRepository.findByUserId(t.userId()).collectList())
                .orElseGet(() -> Mono.just(List.of()));
    }

    private Mono<WebAuthnCeremony> consumeCeremony(UUID ceremonyId, Optional<RegistrationTicket> ticket) {
        if (ceremonyId == null) {
            return Mono.error(new AuthenticationFailedException(AuthRejectionReason.CEREMONY_MISSING));
        }
        var ticketUser = ticket.map(RegistrationTicket::userId).orElse(null);
        return ceremonyRepository.consume(ceremonyId, CeremonyType.AUTHENTICATION)
                .switchIfEmpty(Mono.error(new AuthenticationFailedException(AuthRejectionReason.CEREMONY_INVALID)))
                .flatMap(ceremony -> Objects.equals(ceremony.userId(), ticketUser)
                        ? Mono.just(ceremony)
                        : Mono.error(new AuthenticationFailedException(AuthRejectionReason.CEREMONY_MISMATCH)));
    }

    private Mono<PasskeyAssertion> readAssertion(String credentialJson) {
        return Mono.fromCallable(() -> webAuthnVerifier.readAssertion(credentialJson))
                .onErrorMap(WebAuthnVerificationException.class, e -> {
                    AuthRejectionLog.detail(log, WHAT, e);
                    return new AuthenticationFailedException(AuthRejectionReason.MALFORMED_RESPONSE);
                });
    }

    private Mono<UserPasskey> findPasskey(PasskeyAssertion assertion) {
        return passkeyRepository.findByCredentialId(assertion.credentialId())
                .switchIfEmpty(Mono.error(new UnknownCredentialException()));
    }

    /**
     * The account of the passkey. Discoverable sign-in requires the authenticator's user handle,
     * equal to the account's. With a ticket the credential is already tied to the ticket's
     * account, so a missing user handle is accepted; a present one must still match.
     */
    private Mono<WalletUser> accountOf(UserPasskey passkey, Optional<RegistrationTicket> ticket,
                                       PasskeyAssertion assertion) {
        if (ticket.isPresent() && !ticket.get().userId().equals(passkey.getUserId())) {
            return Mono.error(new AuthenticationFailedException(AuthRejectionReason.TICKET_ACCOUNT_MISMATCH));
        }
        return userRepository.findById(passkey.getUserId())
                .switchIfEmpty(Mono.error(new AuthenticationFailedException(AuthRejectionReason.ACCOUNT_NOT_FOUND)))
                .flatMap(user -> {
                    boolean userHandleAccepted = assertion.userHandle() == null
                            ? ticket.isPresent()
                            : user.hasUserHandle(assertion.userHandle());
                    return userHandleAccepted
                            ? Mono.just(user)
                            : Mono.error(new AuthenticationFailedException(AuthRejectionReason.USER_HANDLE_MISMATCH));
                });
    }

    private Mono<Void> verify(OpenSessionCommand command, WebAuthnCeremony ceremony, UserPasskey passkey) {
        return settingsService.relyingParty()
                .flatMap(relyingParty -> Mono.fromCallable(() -> webAuthnVerifier.verifyAuthentication(
                                command.credentialJson(), ceremony.challenge(), relyingParty, passkey))
                        .onErrorMap(WebAuthnVerificationException.class, e -> {
                            AuthRejectionLog.detail(log, WHAT, e);
                            return new AuthenticationFailedException(AuthRejectionReason.VERIFICATION_FAILED);
                        }))
                .flatMap(verified -> passkeyRepository.recordAuthentication(passkey.getId(), verified))
                .flatMap(updated -> Boolean.TRUE.equals(updated)
                        ? Mono.<Void>empty()
                        : Mono.error(new AuthenticationFailedException(AuthRejectionReason.SIGN_COUNT_NOT_ADVANCED)));
    }

    private Mono<Void> consumeTicket(Optional<RegistrationTicket> ticket) {
        return ticket.map(ticketService::consume).orElseGet(Mono::empty);
    }

    private Mono<Void> auditRejection(UUID ceremonyId, UserPasskey passkey, Throwable e) {
        var reason = e instanceof AuthenticationFailedException failed
                ? failed.getReason()
                : AuthRejectionReason.UNKNOWN_CREDENTIAL;
        AuthRejectionLog.log(log, WHAT, reason);
        var metadata = new HashMap<String, Object>();
        metadata.put("reason", reason.code());
        if (passkey != null) {
            metadata.put("passkey_id", passkey.getId().toString());
        }
        UUID entityId = ceremonyId != null ? ceremonyId : UUID.randomUUID();
        return auditService.record(AuthAuditEvents.ENTITY_CEREMONY, entityId, AuthAuditEvents.ACCESS_REJECTED,
                passkey != null ? passkey.getUserId() : null, metadata);
    }
}
