package com.eudistack.ebw.domain.spi;

import com.eudistack.ebw.domain.model.AccountCreatedNotice;
import com.eudistack.ebw.domain.model.OnboardingAlert;
import reactor.core.publisher.Mono;

import java.util.Locale;

public interface EmailSender {

    Mono<Void> sendOtp(String email, String code);

    /** Tells the account holder that a passkey was added to an account that already had one. */
    Mono<Void> sendNewPasskeyNotice(String email);

    /**
     * Warns the tenant's security contact that the holder of an account created with an onboarding
     * ticket said it was not them (FR-32). Never carries the full email of the holder.
     */
    Mono<Void> sendOnboardingAlert(String securityContact, OnboardingAlert alert, Locale locale);

    /** Tells the holder that their account was created with an onboarding ticket, with the "it was not me" link (FR-29). */
    Mono<Void> sendAccountCreatedNotice(String email, AccountCreatedNotice notice, Locale locale);
}
