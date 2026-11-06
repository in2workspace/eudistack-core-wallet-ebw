package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialOfferReference;
import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.OnboardingTicketIssued;
import com.eudistack.ebw.domain.model.exception.InvalidOnboardingRequestException;
import com.eudistack.ebw.domain.model.exception.OnboardingDisabledException;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Pre-registration requested by an authorized system (design §2.6, FR-22 to FR-26): stores the
 * email, the offer and the system, never an account, and returns the onboarding URL
 * {@code https://<rpId>/t/<ticket>}. The ticket is 16 random bytes (128 bits, 22 base64url
 * characters, AD-8); only its SHA-256 is stored. It lives the tenant's {@code ttl}, or the
 * shorter lifetime the system asks for (EC-03).
 */
@Service
public class CreateOnboardingTicketWorkflow {

    static final int TICKET_BYTES = 16;
    static final String ONBOARDING_PATH = "/t/";

    private final OnboardingSettingsService onboardingSettings;
    private final WalletAuthSettingsService authSettings;
    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final AuditService auditService;

    /**
     * @param expiresIn   lifetime asked by the system, in seconds; {@code null} for the tenant's
     * @param requestedBy identifier of the authenticated system
     */
    public record CreateOnboardingTicketCommand(String email, String credentialOffer, Integer expiresIn,
                                                String requestedBy) {
        @Override
        public String toString() {
            return "CreateOnboardingTicketCommand[email=[redacted], credentialOffer=[redacted], expiresIn="
                    + expiresIn + ", requestedBy=" + requestedBy + "]";
        }
    }

    public CreateOnboardingTicketWorkflow(OnboardingSettingsService onboardingSettings,
                                          WalletAuthSettingsService authSettings,
                                          OnboardingPreregistrationRepository preregistrationRepository,
                                          HashProvider hashProvider, SecureRandomGenerator randomGenerator,
                                          AuditService auditService) {
        this.onboardingSettings = onboardingSettings;
        this.authSettings = authSettings;
        this.preregistrationRepository = preregistrationRepository;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.auditService = auditService;
    }

    public Mono<OnboardingTicketIssued> create(CreateOnboardingTicketCommand command) {
        return onboardingSettings.current()
                .flatMap(settings -> {
                    if (!settings.enabled()) {
                        return Mono.error(new OnboardingDisabledException());
                    }
                    if (command.credentialOffer() != null && !CredentialOfferReference.isValid(command.credentialOffer())) {
                        return Mono.error(new InvalidOnboardingRequestException(
                                "credentialOffer must be an openid-credential-offer:// link with credential_offer_uri"));
                    }
                    var ttl = lifetime(settings.ttl(), command.expiresIn());
                    var ticket = Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(randomGenerator.generateBytes(TICKET_BYTES));
                    var preregistration = OnboardingPreregistration.create(hashProvider.sha256(ticket),
                            command.email(), command.credentialOffer(), command.requestedBy(), ttl);
                    return authSettings.relyingParty()
                            .flatMap(relyingParty -> preregistrationRepository.insert(preregistration)
                                    .then(auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION,
                                            preregistration.id(), AuthAuditEvents.PREREGISTRATION_CREATED, null,
                                            Map.of("requested_by", command.requestedBy())))
                                    .thenReturn(new OnboardingTicketIssued(
                                            "https://" + relyingParty.rpId() + ONBOARDING_PATH + ticket,
                                            ttl.toSeconds())));
                });
    }

    /** EC-03: the system may only shorten the tenant's lifetime. */
    static Duration lifetime(Duration tenantTtl, Integer requestedSeconds) {
        if (requestedSeconds == null || requestedSeconds <= 0) {
            return tenantTtl;
        }
        var requested = Duration.ofSeconds(requestedSeconds);
        return requested.compareTo(tenantTtl) < 0 ? requested : tenantTtl;
    }
}
