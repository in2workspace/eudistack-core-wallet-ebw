package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.EmailSettings;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.model.WalletUser;
import com.eudistack.ebw.domain.repository.WalletUserRepository;
import com.eudistack.ebw.domain.service.EmailSettingsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Locale;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link EmailLocales} (EUD-8 FR-38, AD-10). */
@ExtendWith(MockitoExtension.class)
class EmailLocalesTest {

    @Mock private EmailSettingsService emailSettings;
    @Mock private WalletUserRepository userRepository;

    private EmailLocales locales;

    @BeforeEach
    void setUp() {
        locales = new EmailLocales(emailSettings, userRepository);
        lenient().when(emailSettings.current())
                .thenReturn(Mono.just(new EmailSettings("ca", ZoneId.of("Europe/Madrid"))));
    }

    private static WalletUser userWithLocale(String locale) {
        return new WalletUser(UUID.randomUUID(), "ana@example.com", new byte[32], Instant.now(), Instant.now(), locale);
    }

    @Test
    void ofRequest_requestWithLanguage_isThatLanguage() {
        StepVerifier.create(locales.ofRequest().contextWrite(ctx -> ctx.put(ReactorContextKeys.REQUEST_LANGUAGE, "en")))
                .expectNext(Locale.of("en"))
                .verifyComplete();
    }

    @Test
    void ofRequest_requestWithoutLanguage_isTheTenantDefault() {
        StepVerifier.create(locales.ofRequest()).expectNext(Locale.of("ca")).verifyComplete();
    }

    @Test
    void ofHolder_accountWithLanguage_isThatLanguage() {
        StepVerifier.create(locales.ofHolder(userWithLocale("es"))).expectNext(Locale.of("es")).verifyComplete();
    }

    @Test
    void ofHolder_accountWithoutLanguage_isTheTenantDefault() {
        StepVerifier.create(locales.ofHolder(userWithLocale(null))).expectNext(Locale.of("ca")).verifyComplete();
    }

    @Test
    void rememberRequestLanguage_requestWithLanguage_storesItInTheAccount() {
        var userId = UUID.randomUUID();
        when(userRepository.updateLocale(userId, "en")).thenReturn(Mono.empty());

        StepVerifier.create(locales.rememberRequestLanguage(userId)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.REQUEST_LANGUAGE, "en")))
                .verifyComplete();

        verify(userRepository).updateLocale(userId, "en");
    }

    @Test
    void rememberRequestLanguage_requestWithoutLanguage_keepsTheStoredOne() {
        StepVerifier.create(locales.rememberRequestLanguage(UUID.randomUUID())).verifyComplete();

        verify(userRepository, never()).updateLocale(any(), anyString());
    }

    @Test
    void rememberRequestLanguage_storageFails_neverFailsTheOperation() {
        var userId = UUID.randomUUID();
        when(userRepository.updateLocale(userId, "es")).thenReturn(Mono.error(new IllegalStateException("db")));

        StepVerifier.create(locales.rememberRequestLanguage(userId)
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.REQUEST_LANGUAGE, "es")))
                .verifyComplete();
    }
}
