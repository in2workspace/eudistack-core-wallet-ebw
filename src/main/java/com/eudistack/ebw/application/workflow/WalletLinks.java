package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** Addresses of the tenant's Wallet App used in the emails, built from {@code ebw.wallet_url}. */
@Component
public class WalletLinks {

    /** "Dispositivos" of the Wallet App; without a session it goes through Acceso first (EUD-15 FR-08). */
    static final String DEVICES_PATH = "/tabs/devices";

    private final OnboardingSettingsService onboardingSettings;

    public WalletLinks(OnboardingSettingsService onboardingSettings) {
        this.onboardingSettings = onboardingSettings;
    }

    /**
     * "Dispositivos" of the Wallet App, or empty if the tenant has no valid {@code ebw.wallet_url}: the email then
     * goes without the button, never with an address that does not open the wallet.
     */
    public Mono<String> devices() {
        return onboardingSettings.current()
                .flatMap(settings -> Mono.justOrEmpty(settings.walletUrl()))
                .map(walletUrl -> walletUrl + DEVICES_PATH);
    }
}
