package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.PasskeyRegistrationWorkflow.RegisterPasskeyCommand;
import com.eudistack.ebw.domain.model.AuthRejectionReason;
import com.eudistack.ebw.domain.model.CeremonyType;
import com.eudistack.ebw.domain.model.RegistrationTicket;
import com.eudistack.ebw.domain.model.RelyingPartySettings;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.VerifiedPasskeyRegistration;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.WebAuthnCeremony;
import com.eudistack.ebw.domain.model.exception.RegistrationFailedException;
import com.eudistack.ebw.domain.model.exception.WebAuthnVerificationException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.WebAuthnVerifier;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Steps shared by the registration of a passkey for an account ({@link PasskeyRegistrationWorkflow}) and
 * with an onboarding ticket ({@link RegisterOnboardingPasskeyWorkflow}): the settings of the ceremony,
 * consuming the ceremony bound to the ticket (decision P9), verifying a new credential and storing the passkey.
 */
@Component
class PasskeyRegistrationSteps {

    static final String DEFAULT_DISPLAY_NAME = "Passkey";
    static final String REJECTION_SUBJECT = "Passkey registration";

    private final UserPasskeyRepository passkeyRepository;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final WalletAuthSettingsService settingsService;
    private final PasskeyCustodyPolicy custodyPolicy;
    private final WebAuthnVerifier webAuthnVerifier;
    private final AuditService auditService;

    /** Relying party of the tenant, and whether the tenant keeps the holder key under the passkey. */
    record Settings(RelyingPartySettings relyingParty, boolean passkeyCustody) {}

    PasskeyRegistrationSteps(UserPasskeyRepository passkeyRepository, WebAuthnCeremonyRepository ceremonyRepository,
                             WalletAuthSettingsService settingsService, PasskeyCustodyPolicy custodyPolicy,
                             WebAuthnVerifier webAuthnVerifier, AuditService auditService) {
        this.passkeyRepository = passkeyRepository;
        this.ceremonyRepository = ceremonyRepository;
        this.settingsService = settingsService;
        this.custodyPolicy = custodyPolicy;
        this.webAuthnVerifier = webAuthnVerifier;
        this.auditService = auditService;
    }

    Mono<Settings> settings() {
        return Mono.zip(settingsService.relyingParty(), custodyPolicy.isPasskeyCustody())
                .map(tuple -> new Settings(tuple.getT1(), tuple.getT2()));
    }

    Mono<WebAuthnCeremony> consumeCeremony(UUID ceremonyId, RegistrationTicket ticket) {
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

    /** Verifies the attestation and rejects a credential that is already registered. */
    Mono<VerifiedPasskeyRegistration> verifyNew(String credentialJson, WebAuthnCeremony ceremony,
                                                RelyingPartySettings relyingParty, Logger log) {
        return Mono.fromCallable(() -> webAuthnVerifier.verifyRegistration(credentialJson, ceremony.challenge(),
                        relyingParty))
                .onErrorMap(WebAuthnVerificationException.class, e -> {
                    AuthRejectionLog.detail(log, REJECTION_SUBJECT, e);
                    return new RegistrationFailedException(AuthRejectionReason.VERIFICATION_FAILED);
                })
                .flatMap(verified -> passkeyRepository.findByCredentialId(verified.credentialId())
                        .flatMap(existing -> Mono.<VerifiedPasskeyRegistration>error(new RegistrationFailedException(
                                AuthRejectionReason.CREDENTIAL_ALREADY_REGISTERED)))
                        .defaultIfEmpty(verified));
    }

    Mono<UserPasskey> storePasskey(RegisterPasskeyCommand command, WalletUser user,
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
}
