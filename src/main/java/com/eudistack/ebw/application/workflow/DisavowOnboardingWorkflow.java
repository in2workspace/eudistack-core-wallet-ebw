package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.OnboardingAlert;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.model.exception.InvalidDisavowalTokenException;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * "It was not me" of an account created with an onboarding ticket (design §2.6, FR-32, AC-10).
 * Consumes the single-use token and, in one transaction, ends every session of the account,
 * removes the passkey registered with the ticket and leaves the trace. Then warns the tenant's
 * security contact; if that fails the disavowal still stands and {@code ONBOARDING_ALERT_FAILED}
 * is traced. The account stays without that passkey: the holder recovers access with the email.
 *
 * <p>The devices registered with the passkey are revoked by the device management (EUD-15), not
 * implemented yet (decision P5).
 */
@Slf4j
@Service
public class DisavowOnboardingWorkflow {

    static final Duration ALERT_TIMEOUT = Duration.ofSeconds(5);
    /**
     * PROVISIONAL (EUD-315 decision P10): the alert goes in the tenant's default language, and
     * {@code ebw.default_locale} does not exist yet; every email of the service is English today.
     */
    static final Locale ALERT_LOCALE = Locale.ENGLISH;
    static final String ENTITY_DISAVOWAL = "onboarding_disavowal";

    private final OnboardingDisavowalRepository disavowalRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserPasskeyRepository passkeyRepository;
    private final WalletUserRepository userRepository;
    private final OnboardingSettingsService onboardingSettings;
    private final EmailSender emailSender;
    private final HashProvider hashProvider;
    private final TransactionRunner transactionRunner;
    private final AuditService auditService;

    @SuppressWarnings("java:S107")
    public DisavowOnboardingWorkflow(OnboardingDisavowalRepository disavowalRepository,
                                     RefreshTokenRepository refreshTokenRepository,
                                     UserPasskeyRepository passkeyRepository, WalletUserRepository userRepository,
                                     OnboardingSettingsService onboardingSettings, EmailSender emailSender,
                                     HashProvider hashProvider, TransactionRunner transactionRunner,
                                     AuditService auditService) {
        this.disavowalRepository = disavowalRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passkeyRepository = passkeyRepository;
        this.userRepository = userRepository;
        this.onboardingSettings = onboardingSettings;
        this.emailSender = emailSender;
        this.hashProvider = hashProvider;
        this.transactionRunner = transactionRunner;
        this.auditService = auditService;
    }

    public Mono<Void> disavow(String rawToken) {
        return transactionRunner.inTransaction(disavowalRepository.consume(hashProvider.sha256(rawToken))
                        .switchIfEmpty(Mono.error(new InvalidDisavowalTokenException()))
                        .flatMap(disavowal -> undo(disavowal).thenReturn(disavowal)))
                .flatMap(this::alert);
    }

    private Mono<Void> undo(OnboardingDisavowal disavowal) {
        var removePasskey = disavowal.passkeyId() == null
                ? Mono.<Boolean>just(false)
                : passkeyRepository.findByIdAndUserId(disavowal.passkeyId(), disavowal.userId())
                        .flatMap(passkey -> passkeyRepository.deleteById(passkey.getId()).thenReturn(true))
                        .defaultIfEmpty(false);
        return refreshTokenRepository.revokeByUserId(disavowal.userId())
                .then(removePasskey)
                .flatMap(removed -> auditService.record(ENTITY_DISAVOWAL, disavowal.id(),
                        AuthAuditEvents.ONBOARDING_DISAVOWED, disavowal.userId(),
                        Map.of("requested_by", disavowal.requestedBy(), "passkey_removed", removed)));
    }

    /** After the transaction: a failed alert never undoes the disavowal. */
    private Mono<Void> alert(OnboardingDisavowal disavowal) {
        return onboardingSettings.current()
                .flatMap(settings -> settings.securityContact() == null || settings.securityContact().isBlank()
                        ? alertFailed(disavowal, "no_security_contact")
                        : userRepository.findById(disavowal.userId())
                                .flatMap(user -> emailSender.sendOnboardingAlert(settings.securityContact(),
                                        new OnboardingAlert(OnboardingAlert.mask(user.getEmail()),
                                                disavowal.registeredAt(), disavowal.requestedBy()),
                                        ALERT_LOCALE))
                                .timeout(ALERT_TIMEOUT))
                .onErrorResume(e -> {
                    // Class only: a mail error may echo the addresses.
                    log.warn("Onboarding alert not sent: {}", e.getClass().getSimpleName());
                    return alertFailed(disavowal, "send_failed");
                });
    }

    private Mono<Void> alertFailed(OnboardingDisavowal disavowal, String reason) {
        return auditService.record(ENTITY_DISAVOWAL, disavowal.id(), AuthAuditEvents.ONBOARDING_ALERT_FAILED,
                disavowal.userId(), Map.of("reason", reason));
    }
}
