package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.EmailLanguage;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.EmailSettingsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.UUID;

/**
 * Language of each email (EUD-8 FR-38, AD-10). The holder's emails go in the language stored in the account,
 * the Wallet App's at its last session; the code, which may go to an email without account, in the language of
 * its request; and the alert to the security contact, like anything without a known language, in the tenant's
 * {@code ebw.default_locale}.
 */
@Slf4j
@Component
public class EmailLocales {

    private final EmailSettingsService emailSettings;
    private final WalletUserRepository userRepository;

    public EmailLocales(EmailSettingsService emailSettings, WalletUserRepository userRepository) {
        this.emailSettings = emailSettings;
        this.userRepository = userRepository;
    }

    /** The language of the request ({@code Accept-Language}) or, without one, the tenant's. */
    public Mono<Locale> ofRequest() {
        return Mono.deferContextual(ctx -> ctx.<String>getOrEmpty(ReactorContextKeys.REQUEST_LANGUAGE)
                .map(language -> Mono.just(Locale.of(language)))
                .orElseGet(this::tenantDefault));
    }

    /** The language stored in the account or, without one, the tenant's. */
    public Mono<Locale> ofHolder(WalletUser user) {
        return EmailLanguage.parse(user.getLocale())
                .map(language -> Mono.just(Locale.of(language)))
                .orElseGet(this::tenantDefault);
    }

    /** The tenant's {@code ebw.default_locale}. */
    public Mono<Locale> tenantDefault() {
        return emailSettings.current().map(settings -> Locale.of(settings.defaultLanguage()));
    }

    /**
     * Stores the language of the request in the account, if the request has one (opening a session, registering
     * or binding a Wallet Instance). Best effort: a failure never fails the operation.
     */
    public Mono<Void> rememberRequestLanguage(UUID userId) {
        return Mono.deferContextual(ctx -> ctx.<String>getOrEmpty(ReactorContextKeys.REQUEST_LANGUAGE)
                .map(language -> userRepository.updateLocale(userId, language)
                        .onErrorResume(e -> {
                            log.warn("Could not store the language of the account: {}", e.getClass().getSimpleName());
                            return Mono.empty();
                        }))
                .orElseGet(Mono::empty));
    }
}
