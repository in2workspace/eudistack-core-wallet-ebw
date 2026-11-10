package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingDisavowal;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.domain.spi.EmailSender;
import com.eudistack.ebw.domain.spi.HashProvider;
import com.eudistack.ebw.domain.spi.SecureRandomGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * New-account email of an account created with an onboarding ticket, with the single-use "it was
 * not me" link (design §2.6, FR-29). The token is generated here, when the email is sent, and
 * given to the row the registration left without one (decision P6): only its SHA-256 is stored,
 * and the conditional update makes the email go out once. Best effort: a failure is traced as
 * {@code ONBOARDING_NOTICE_FAILED} and never undoes the onboarding; the email is not retried.
 *
 * <p>The design sends it when the first device of the account is registered, by the device
 * management (EUD-15), which does not exist yet. PROVISIONAL (EUD-315 decision P5): the passkey
 * registration calls it right after its commit, with the passkey name as the device. EUD-15 moves
 * the call to its device registration.
 */
@Slf4j
@Service
public class NotifyOnboardingAccountCreatedWorkflow {

    static final int TOKEN_BYTES = 32;
    static final Duration NOTICE_TIMEOUT = Duration.ofSeconds(5);
    /** In the fragment, which never leaves the browser: not in access logs nor in Referer (P18). */
    static final String DISAVOWAL_PATH = "/no-he-sido-yo#";
    /** PROVISIONAL (EUD-315 decision P10): the language of the account does not exist yet. */
    static final Locale NOTICE_LOCALE = Locale.ENGLISH;

    private final OnboardingDisavowalRepository disavowalRepository;
    private final WalletUserRepository userRepository;
    private final WalletAuthSettingsService authSettings;
    private final EmailSender emailSender;
    private final HashProvider hashProvider;
    private final SecureRandomGenerator randomGenerator;
    private final AuditService auditService;

    @SuppressWarnings("java:S107")
    public NotifyOnboardingAccountCreatedWorkflow(OnboardingDisavowalRepository disavowalRepository,
                                                  WalletUserRepository userRepository,
                                                  WalletAuthSettingsService authSettings, EmailSender emailSender,
                                                  HashProvider hashProvider, SecureRandomGenerator randomGenerator,
                                                  AuditService auditService) {
        this.disavowalRepository = disavowalRepository;
        this.userRepository = userRepository;
        this.authSettings = authSettings;
        this.emailSender = emailSender;
        this.hashProvider = hashProvider;
        this.randomGenerator = randomGenerator;
        this.auditService = auditService;
    }

    /**
     * @param passkeyId  passkey registered with the onboarding ticket
     * @param deviceName device shown in the email
     */
    public Mono<Void> notify(UUID passkeyId, String deviceName) {
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
                        }))
                .onErrorResume(e -> {
                    log.warn("New-account email not prepared: {}", e.getClass().getSimpleName());
                    return Mono.empty();
                });
    }

    private Mono<Void> send(OnboardingDisavowal disavowal, String token, String deviceName) {
        return Mono.zip(userRepository.findById(disavowal.userId()), authSettings.relyingParty())
                .flatMap(tuple -> emailSender.sendAccountCreatedNotice(tuple.getT1().getEmail(),
                        new AccountCreatedNotice(disavowal.registeredAt(), disavowal.requestedBy(), deviceName,
                                "https://" + tuple.getT2().rpId() + DISAVOWAL_PATH + token,
                                disavowal.expiresAt()),
                        NOTICE_LOCALE))
                .timeout(NOTICE_TIMEOUT);
    }
}
