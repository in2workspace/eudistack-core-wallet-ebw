package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Email of a passkey registered with an onboarding ticket, for a new account and for one that already
 * existed (decision P17), with the single-use "it was not me" link (design §2.6, FR-29). The token is generated here, when the email is sent, and
 * given to the row the registration left without one (decision P6): only its SHA-256 is stored,
 * and the conditional update makes the email go out once. Best effort: a failure is traced as
 * {@code ONBOARDING_NOTICE_FAILED} and never undoes the onboarding; the email is not retried.
 *
 * <p>It is the email that ends the registration of the first device of the account (EUD-15 FR-08, design
 * §2.1): {@link WalletInstanceNotices} sends it after the device is registered, with its name, in the language
 * of the account. A holder who leaves on "Registrar este dispositivo" gets it when they register it on their
 * next entry, while the row lives (7 days).
 */
@Slf4j
@Service
public class NotifyOnboardingAccountCreatedWorkflow {

    static final int TOKEN_BYTES = 32;
    static final Duration NOTICE_TIMEOUT = Duration.ofSeconds(5);
    /** In the fragment, which never leaves the browser: not in access logs nor in Referer (P18). */
    static final String DISAVOWAL_PATH = "/not-me#";

    private final OnboardingDisavowalRepository disavowalRepository;
    private final WalletUserRepository userRepository;
    private final OnboardingSettingsService onboardingSettings;
    private final EmailSender emailSender;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final AuditService auditService;
    private final EmailLocales emailLocales;

    @SuppressWarnings("java:S107")
    public NotifyOnboardingAccountCreatedWorkflow(OnboardingDisavowalRepository disavowalRepository,
                                                  WalletUserRepository userRepository,
                                                  OnboardingSettingsService onboardingSettings,
                                                  EmailSender emailSender,
                                                  HashProvider hashProvider, SecureRandomGenerator randomGenerator,
                                                  AuditService auditService, EmailLocales emailLocales) {
        this.disavowalRepository = disavowalRepository;
        this.userRepository = userRepository;
        this.onboardingSettings = onboardingSettings;
        this.emailSender = emailSender;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.auditService = auditService;
        this.emailLocales = emailLocales;
    }

    /**
     * Sends the email if the passkey still owes it.
     *
     * @param passkeyId  passkey registered with the onboarding ticket (the passkey of the session)
     * @param deviceName name of the device whose registration sends it (EUD-15 FR-08, AC-09)
     * @return {@code true} when the passkey owed it (sent, or failed and traced), {@code false} when it did not:
     *         not registered with a ticket, or already sent. Never errors.
     */
    public Mono<Boolean> notify(UUID passkeyId, String deviceName) {
        var token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomGenerator.generateBytes(TOKEN_BYTES));
        var expiresAt = Instant.now().plus(OnboardingDisavowal.TTL);
        return disavowalRepository.assignToken(passkeyId, hashProvider.sha256(token), expiresAt)
                .flatMap(disavowal -> send(disavowal, token, deviceName)
                        .then(auditService.record(DisavowOnboardingWorkflow.ENTITY_DISAVOWAL, disavowal.id(),
                                AuthAuditEvents.ONBOARDING_NOTICE_SENT, disavowal.userId(), Map.of()))
                        .onErrorResume(e -> {
                            // Class only: a mail error may echo the address.
                            log.warn("New-account email not sent: {}", e.getClass().getSimpleName());
                            return auditService.record(DisavowOnboardingWorkflow.ENTITY_DISAVOWAL, disavowal.id(),
                                            AuthAuditEvents.ONBOARDING_NOTICE_FAILED, disavowal.userId(), Map.of())
                                    .onErrorResume(auditError -> Mono.empty());
                        })
                        .thenReturn(true))
                .defaultIfEmpty(false)
                .onErrorResume(e -> {
                    log.warn("New-account email not prepared: {}", e.getClass().getSimpleName());
                    return Mono.just(false);
                });
    }

    private Mono<Void> send(OnboardingDisavowal disavowal, String token, String deviceName) {
        // The link points at the tenant's Wallet App (ebw.wallet_url, task 44); without it, the email fails.
        return Mono.zip(userRepository.findById(disavowal.userId()), onboardingSettings.walletUrl())
                .flatMap(tuple -> emailLocales.ofHolder(tuple.getT1())
                        .flatMap(locale -> emailSender.sendAccountCreatedNotice(tuple.getT1().getEmail(),
                                new AccountCreatedNotice(disavowal.registeredAt(),
                                        tuple.getT2() + DISAVOWAL_PATH + token,
                                        disavowal.expiresAt(), disavowal.accountCreated(), deviceName),
                                locale)))
                .timeout(NOTICE_TIMEOUT);
    }
}
