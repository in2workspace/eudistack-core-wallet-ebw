package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.OnboardingPreregistration;
import com.eudistack.ebw.domain.model.OnboardingTicketRedemption;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.model.exception.InvalidTicketException;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.RegistrationTicketService;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Redemption of an onboarding ticket (design §2.6, FR-27, FR-28, FR-30, FR-31). Consumes the
 * ticket atomically and never creates an account nor opens a session:
 * <ul>
 *   <li>active session of the ticket's account: {@code sessionOfAccount}, no registration ticket,
 *       the pre-registration is deleted;</li>
 *   <li>account with passkeys: no registration ticket, the pre-registration is deleted (FR-28);</li>
 *   <li>account without passkeys, or no account: a registration ticket bound to the
 *       pre-registration. Without an account, the WebAuthn user handle of the future account is
 *       generated here and kept in the pre-registration (decision P2, provisional).</li>
 * </ul>
 * The offer comes back in every case. The trace never carries the email nor the ticket.
 */
@Service
public class RedeemOnboardingTicketWorkflow {

    static final String OUTCOME = "outcome";
    static final String OUTCOME_REGISTRATION = "registration";
    static final String OUTCOME_HAS_PASSKEYS = "has_passkeys";
    static final String OUTCOME_SESSION_OF_ACCOUNT = "session_of_account";

    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final WalletUserRepository userRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final RegistrationTicketService ticketService;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final AuditService auditService;

    @SuppressWarnings("java:S107")
    public RedeemOnboardingTicketWorkflow(OnboardingPreregistrationRepository preregistrationRepository,
                                          WalletUserRepository userRepository,
                                          UserPasskeyRepository passkeyRepository,
                                          RegistrationTicketService ticketService, HashProvider hashProvider,
                                          SecureRandomGenerator randomGenerator, AuditService auditService) {
        this.preregistrationRepository = preregistrationRepository;
        this.userRepository = userRepository;
        this.passkeyRepository = passkeyRepository;
        this.ticketService = ticketService;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.auditService = auditService;
    }

    /**
     * @param rawTicket     the onboarding ticket of the address
     * @param sessionUserId account of the active session the request carried, {@code null} without one
     */
    public Mono<OnboardingTicketRedemption> redeem(String rawTicket, UUID sessionUserId) {
        return preregistrationRepository.redeem(hashProvider.sha256(rawTicket))
                .switchIfEmpty(Mono.defer(this::reject))
                .flatMap(preregistration -> userRepository.findByEmail(preregistration.email())
                        .flatMap(user -> forAccount(preregistration, user, sessionUserId))
                        .switchIfEmpty(Mono.defer(() -> withoutAccount(preregistration))));
    }

    private Mono<OnboardingTicketRedemption> forAccount(OnboardingPreregistration preregistration, WalletUser user,
                                                        UUID sessionUserId) {
        if (user.getId().equals(sessionUserId)) {
            return close(preregistration, user.getId(), OUTCOME_SESSION_OF_ACCOUNT)
                    .thenReturn(new OnboardingTicketRedemption(true, true, null, null,
                            preregistration.credentialOffer()));
        }
        return passkeyRepository.countByUserId(user.getId())
                .defaultIfEmpty(0L)
                .flatMap(count -> count > 0
                        ? close(preregistration, user.getId(), OUTCOME_HAS_PASSKEYS)
                                .thenReturn(new OnboardingTicketRedemption(true, false, null, null,
                                        preregistration.credentialOffer()))
                        : registration(preregistration, user.getId()));
    }

    private Mono<OnboardingTicketRedemption> withoutAccount(OnboardingPreregistration preregistration) {
        return preregistrationRepository.assignUserHandle(preregistration.id(),
                        randomGenerator.generateBytes(WalletUser.USER_HANDLE_LENGTH))
                .then(registration(preregistration, null));
    }

    private Mono<OnboardingTicketRedemption> registration(OnboardingPreregistration preregistration, UUID userId) {
        return ticketService.issueForPreregistration(userId, preregistration.id())
                .flatMap(ticket -> preregistrationRepository.keepUntil(preregistration.id(), ticket.expiresAt())
                        .then(redeemed(preregistration, userId, OUTCOME_REGISTRATION))
                        .thenReturn(new OnboardingTicketRedemption(false, false, ticket.raw(),
                                secondsUntil(ticket.expiresAt()), preregistration.credentialOffer())));
    }

    /** The ticket gives no registration: the pre-registration is no longer needed (FR-25). */
    private Mono<Void> close(OnboardingPreregistration preregistration, UUID userId, String outcome) {
        return preregistrationRepository.deleteById(preregistration.id())
                .then(redeemed(preregistration, userId, outcome));
    }

    private Mono<Void> redeemed(OnboardingPreregistration preregistration, UUID userId, String outcome) {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, preregistration.id(),
                AuthAuditEvents.ONBOARDING_TICKET_REDEEMED, userId,
                Map.of(OUTCOME, outcome, "requested_by", preregistration.requestedBy()));
    }

    /** Unknown, used, expired or of another tenant: the same answer, and the trace has no ticket. */
    private Mono<OnboardingPreregistration> reject() {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, UUID.randomUUID(),
                        AuthAuditEvents.ONBOARDING_TICKET_REJECTED, null, Map.of())
                .then(Mono.error(new InvalidTicketException()));
    }

    private static long secondsUntil(Instant expiresAt) {
        var millis = Duration.between(Instant.now(), expiresAt).toMillis();
        return Math.max(0, (millis + 999) / 1000);
    }
}
