package com.eudistack.ebw.domain.spi;

import com.eudistack.ebw.domain.model.AccountCompleteNotice;
import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.NewDeviceNotice;
import com.eudistack.ebw.domain.model.NewPasskeyNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import reactor.core.publisher.Mono;

import java.util.Locale;

/**
 * The wallet's emails, with the content of the wireframes of EUD-8 and EUD-15, the tenant's branding as sender
 * and header, and the dates in the tenant's time zone. Each one goes in the {@code locale} the caller chooses
 * (EUD-8 FR-38, AD-10).
 */
public interface EmailSender {

    /** The sign-in code. The same email whether the address has an account or not (FR-05). */
    Mono<Void> sendOtp(String email, String code, Locale locale);

    /**
     * Tells the holder that a passkey was added to an account that already had one, when the session that added
     * it did not register a new device (EUD-8 FR-10).
     */
    Mono<Void> sendNewPasskeyNotice(String email, NewPasskeyNotice notice, Locale locale);

    /**
     * Warns the tenant's security contact that the holder of an account created with an onboarding
     * ticket said it was not them (FR-32). Never carries the full email of the holder.
     */
    Mono<Void> sendOnboardingAlert(String securityContact, OnboardingAlert alert, Locale locale);

    /**
     * Tells the holder that their account was created with an onboarding ticket, with the "it was not me" link
     * (FR-29), once its first device is registered (EUD-15 FR-08).
     */
    Mono<Void> sendAccountCreatedNotice(String email, AccountCreatedNotice notice, Locale locale);

    /** Confirms the complete sign-up with the name of the first device (EUD-15 FR-08, "Alta completa"). */
    Mono<Void> sendAccountCompleteNotice(String email, AccountCompleteNotice notice, Locale locale);

    /** Tells the holder that a new device was registered in the account (EUD-15 FR-08, "Dispositivo nuevo"). */
    Mono<Void> sendNewDeviceNotice(String email, NewDeviceNotice notice, Locale locale);
}
