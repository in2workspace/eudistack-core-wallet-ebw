package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.domain.model.NewPasskeyNotice;
import com.eudistack.ebw.domain.model.WalletInstance;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.EmailSender;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The single email that ends the registration of a device (EUD-15 FR-08, design §2.1), and the new-passkey
 * email of a session that does not register one (EUD-8 FR-10, AD-11). All of them in the language of the
 * account and best effort: a failed or slow (over {@link #NOTICE_TIMEOUT}) email is traced and never fails the
 * operation, and it is not retried.
 */
@Slf4j
@Component
public class WalletInstanceNotices {

    static final Duration NOTICE_TIMEOUT = Duration.ofSeconds(5);

    /** What the registration of a device knows when it sends its email. */
    public record Registration(WalletUser user, WalletInstance instance, boolean firstOfNewAccount,
                               boolean passkeyAdded) {}

    private final EmailSender emailSender;
    private final EmailLocales emailLocales;
    private final WalletLinks walletLinks;
    private final AuditService auditService;
    private final NotifyOnboardingAccountCreatedWorkflow onboardingNotice;

    public WalletInstanceNotices(EmailSender emailSender, EmailLocales emailLocales, WalletLinks walletLinks,
                                 AuditService auditService, NotifyOnboardingAccountCreatedWorkflow onboardingNotice) {
        this.emailSender = emailSender;
        this.emailLocales = emailLocales;
        this.walletLinks = walletLinks;
        this.auditService = auditService;
        this.onboardingNotice = onboardingNotice;
    }

    /**
     * After the registration of a device commits. A passkey registered with an onboarding ticket that still owes
     * its email gets the new-account email with "it was not me" ({@code ONBOARDING_NOTICE_*}); otherwise the
     * first device of a new account gets the complete sign-up email, and any other device the new-device email,
     * which says so if a passkey was added in the session ({@code WALLET_INSTANCE_NOTICE_*}). Never errors.
     */
    public Mono<Void> deviceRegistered(Registration registration) {
        var instance = registration.instance();
        return onboardingNotice.notify(instance.registeredPasskeyId(), instance.displayName())
                .flatMap(sentAsOnboarding -> Boolean.TRUE.equals(sentAsOnboarding)
                        ? Mono.<Void>empty()
                        : traced(instance, registration.user(), sendDeviceEmail(registration)));
    }

    /**
     * A session bound to a device that already existed. A passkey registered with an onboarding ticket that still
     * owes its new-account email gets it now, with the name of that device. Emits whether it did. Never errors.
     */
    public Mono<Boolean> sessionBound(UUID passkeyId, WalletInstance instance) {
        return onboardingNotice.notify(passkeyId, instance.displayName());
    }

    /** The new-passkey email: a session that added a passkey bound to an existing device, or ended without one. */
    public Mono<Void> passkeyAdded(WalletUser user, UUID passkeyId, Instant addedAt) {
        return walletLinks.devices().map(Optional::of).defaultIfEmpty(Optional.empty())
                .flatMap(devicesUrl -> emailLocales.ofHolder(user)
                        .flatMap(locale -> emailSender.sendNewPasskeyNotice(user.getEmail(),
                                new NewPasskeyNotice(addedAt, devicesUrl.orElse(null)), locale)))
                .timeout(NOTICE_TIMEOUT)
                .then(auditService.record(AuthAuditEvents.ENTITY_PASSKEY, passkeyId,
                        AuthAuditEvents.NEW_PASSKEY_NOTICE_SENT, user.getId(), Map.of()))
                .onErrorResume(e -> {
                    // Class only: a mail error may echo the address.
                    log.warn("New passkey notice not sent: {}", e.getClass().getSimpleName());
                    return auditService.record(AuthAuditEvents.ENTITY_PASSKEY, passkeyId,
                                    AuthAuditEvents.NEW_PASSKEY_NOTICE_FAILED, user.getId(), Map.of())
                            .onErrorResume(auditError -> Mono.empty());
                });
    }

    private Mono<Void> sendDeviceEmail(Registration registration) {
        var user = registration.user();
        var instance = registration.instance();
        return emailLocales.ofHolder(user).flatMap(locale -> {
            // The complete sign-up email says nothing of a passkey: if the session added one to an account that
            // already had another, the new-device email goes instead, so that notice is never lost (EUD-8 FR-10).
            if (registration.firstOfNewAccount() && !registration.passkeyAdded()) {
                return emailSender.sendAccountCompleteNotice(user.getEmail(),
                        new AccountCompleteNotice(instance.createdAt(), instance.displayName()), locale);
            }
            return walletLinks.devices().map(Optional::of).defaultIfEmpty(Optional.empty())
                    .flatMap(devicesUrl -> emailSender.sendNewDeviceNotice(user.getEmail(),
                            new NewDeviceNotice(instance.createdAt(), instance.displayName(),
                                    registration.passkeyAdded(), devicesUrl.orElse(null)), locale));
        });
    }

    private Mono<Void> traced(WalletInstance instance, WalletUser user, Mono<Void> send) {
        return send.timeout(NOTICE_TIMEOUT)
                .then(auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                        WalletInstanceAuditEvents.WALLET_INSTANCE_NOTICE_SENT, user.getId(), Map.of()))
                .onErrorResume(e -> {
                    log.warn("Device registration notice not sent: {}", e.getClass().getSimpleName());
                    return auditService.record(WalletInstanceAuditEvents.ENTITY_WALLET_INSTANCE, instance.id(),
                                    WalletInstanceAuditEvents.WALLET_INSTANCE_NOTICE_FAILED, user.getId(), Map.of())
                            .onErrorResume(auditError -> Mono.empty());
                });
    }
}
