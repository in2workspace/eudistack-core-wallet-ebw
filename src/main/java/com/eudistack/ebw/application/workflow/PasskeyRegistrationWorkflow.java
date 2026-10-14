package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.IssuedSession;
import com.eudistack.ebw.domain.model.RegistrationOptions;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.model.exception.PasskeyPrfUnsupportedException;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Registration ceremony of a new passkey with a registration ticket (FR-07, FR-08, FR-10).
 *
 * <p>The ceremony is consumed before verifying anything. With passkey custody in the tenant,
 * a passkey without PRF is rejected and nothing is stored. The ticket is consumed when the
 * session is opened. If the account already had a passkey, the account holder is emailed
 * after the new one is stored; a failed email never fails the registration.
 */
@Service
public class PasskeyRegistrationWorkflow {

    static final String DEFAULT_DISPLAY_NAME = "Passkey";

    private static final Logger log = LoggerFactory.getLogger(PasskeyRegistrationWorkflow.class);

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

    /** Input of {@link #register}. {@code replacedRefreshToken} is the refresh cookie of the request, if any. */
    public record RegisterPasskeyCommand(String rawTicket, UUID ceremonyId, String credentialJson,
                                         Boolean prfSupported, String displayName, String userAgent,
                                         String replacedRefreshToken) {}

    @SuppressWarnings("java:S107")
    public PasskeyRegistrationWorkflow(RegistrationTicketService ticketService, WalletUserRepository userRepository,
                                       UserPasskeyRepository passkeyRepository,
                                       WebAuthnCeremonyRepository ceremonyRepository,
                                       WalletAuthSettingsService settingsService, PasskeyCustodyPolicy custodyPolicy,
                                       WebAuthnVerifier webAuthnVerifier, SecureRandomGenerator randomGenerator,
                                       SessionOpener sessionOpener, EmailSender emailSender,
                                       AuditService auditService) {
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
    }

    public Mono<RegistrationOptions> startRegistration(String rawTicket) {
        return ticketService.resolve(rawTicket)
                .flatMap(this::accountOf)
                .flatMap(user -> Mono.zip(settingsService.relyingParty(), custodyPolicy.isPasskeyCustody(),
                                passkeyRepository.findByUserId(user.getId()).collectList())
                        .flatMap(tuple -> {
                            var ceremony = WebAuthnCeremony.start(CeremonyType.REGISTRATION,
                                    randomGenerator.generateBytes(WebAuthnCeremony.CHALLENGE_LENGTH), user.getId());
                            return ceremonyRepository.insert(ceremony)
                                    .thenReturn(new RegistrationOptions(ceremony.id(), tuple.getT1(),
                                            user.getWebauthnUserHandle(), user.getEmail(), ceremony.challenge(),
                                            tuple.getT3(), tuple.getT2()));
                        }));
    }

    public Mono<IssuedSession> register(RegisterPasskeyCommand command) {
        return ticketService.resolve(command.rawTicket())
                .flatMap(ticket -> consumeCeremony(command.ceremonyId(), ticket)
                        .flatMap(ceremony -> accountOf(ticket)
                                .flatMap(user -> Mono.zip(settingsService.relyingParty(),
                                                custodyPolicy.isPasskeyCustody())
                                        .flatMap(tuple -> registerVerified(command, ticket, ceremony, user,
                                                tuple.getT1(), tuple.getT2())))));
    }

    private Mono<IssuedSession> registerVerified(RegisterPasskeyCommand command, RegistrationTicket ticket,
                                                 WebAuthnCeremony ceremony, WalletUser user,
                                                 RelyingPartySettings relyingParty, boolean passkeyCustody) {
        boolean prfSupported = Boolean.TRUE.equals(command.prfSupported());
        if (passkeyCustody && !prfSupported) {
            return auditRejection(user, "prf_unsupported")
                    .then(Mono.error(new PasskeyPrfUnsupportedException()));
        }
        return verify(command.credentialJson(), ceremony, relyingParty)
                .flatMap(verified -> passkeyRepository.findByCredentialId(verified.credentialId())
                        .flatMap(existing -> Mono.<VerifiedPasskeyRegistration>error(
                                new RegistrationFailedException("credential already registered in the tenant")))
                        .defaultIfEmpty(verified))
                .onErrorResume(RegistrationFailedException.class, e -> {
                    log.info("Passkey registration rejected: {}", e.getMessage());
                    return auditRejection(user, "verification_failed").then(Mono.error(e));
                })
                .flatMap(verified -> ticketService.consume(ticket)
                        .then(passkeyRepository.countByUserId(user.getId()).defaultIfEmpty(0L))
                        .flatMap(previousPasskeys -> storePasskey(command, user, verified, prfSupported)
                                .flatMap(passkey -> sessionOpener.open(user, passkey.getId(),
                                                command.replacedRefreshToken(), "registration")
                                        .flatMap(session -> previousPasskeys > 0
                                                ? notifyNewPasskey(user, passkey).thenReturn(session)
                                                : Mono.just(session)))));
    }

    private Mono<VerifiedPasskeyRegistration> verify(String credentialJson, WebAuthnCeremony ceremony,
                                                     RelyingPartySettings relyingParty) {
        return Mono.fromCallable(() -> webAuthnVerifier.verifyRegistration(credentialJson, ceremony.challenge(),
                        relyingParty))
                .onErrorMap(WebAuthnVerificationException.class,
                        e -> new RegistrationFailedException(e.getMessage()));
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
            return Mono.error(new RegistrationFailedException("missing ceremony"));
        }
        return ceremonyRepository.consume(ceremonyId, CeremonyType.REGISTRATION)
                .switchIfEmpty(Mono.error(new RegistrationFailedException("ceremony unknown, expired or used")))
                .flatMap(ceremony -> Objects.equals(ceremony.userId(), ticket.userId())
                        ? Mono.just(ceremony)
                        : Mono.error(new RegistrationFailedException("ceremony of another account")));
    }

    private Mono<WalletUser> accountOf(RegistrationTicket ticket) {
        return userRepository.findById(ticket.userId())
                .switchIfEmpty(Mono.error(new InvalidTicketException()));
    }

    private Mono<Void> auditRejection(WalletUser user, String reason) {
        return auditService.record(AuthAuditEvents.ENTITY_USER, user.getId(), AuthAuditEvents.PASSKEY_REJECTED,
                user.getId(), Map.of("reason", reason));
    }

    /** FR-10: best-effort. A failed email is logged and never fails the registration. */
    private Mono<Void> notifyNewPasskey(WalletUser user, UserPasskey passkey) {
        return emailSender.sendNewPasskeyNotice(user.getEmail())
                .then(auditService.record(AuthAuditEvents.ENTITY_PASSKEY, passkey.getId(),
                        AuthAuditEvents.NEW_PASSKEY_NOTICE_SENT, user.getId(), Map.of()))
                .onErrorResume(e -> {
                    log.warn("Could not send the new passkey notice for passkey {}: {}", passkey.getId(),
                            e.getClass().getName());
                    return Mono.empty();
                });
    }
}
