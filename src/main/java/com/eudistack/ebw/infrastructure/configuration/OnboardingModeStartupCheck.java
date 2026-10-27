package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.OnboardingSettingsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * At startup, after the tenant migrations, logs an ERROR for every active tenant in onboarding
 * mode {@code restricted} without onboarding tickets enabled or without a signup URL (design
 * §2.7): nobody can create an account in it, or the Wallet App cannot tell where to get one. The
 * tenant stays restricted: a configuration error never opens the onboarding. Never blocks nor
 * fails the startup.
 */
@Slf4j
@Component
@Order(3)
public class OnboardingModeStartupCheck implements ApplicationRunner {

    private final ActiveTenantDirectory tenantDirectory;
    private final OnboardingSettingsService settingsService;

    public OnboardingModeStartupCheck(ActiveTenantDirectory tenantDirectory,
                                      OnboardingSettingsService settingsService) {
        this.tenantDirectory = tenantDirectory;
        this.settingsService = settingsService;
    }

    @Override
    public void run(ApplicationArguments args) {
        misconfiguredRestrictedTenants().subscribe();
    }

    /** Emits the restricted tenants without onboarding tickets or signup URL, each logged as ERROR. */
    public Mono<List<String>> misconfiguredRestrictedTenants() {
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> settingsService.current()
                        .filter(settings -> settings.restricted()
                                && (!settings.enabled() || settings.signupUrl() == null))
                        .map(settings -> {
                            log.error("Tenant '{}' is in onboarding mode 'restricted' without {}: users without "
                                            + "an account cannot get one in the wallet", tenant,
                                    settings.enabled() ? "'" + OnboardingSettingsService.SIGNUP_URL + "'"
                                            : "'" + OnboardingSettingsService.ENABLED + "'");
                            return tenant;
                        })
                        .onErrorResume(e -> {
                            log.warn("Could not check the onboarding mode of tenant '{}': {}", tenant,
                                    e.getClass().getSimpleName());
                            return Mono.empty();
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .collectList()
                .onErrorResume(e -> {
                    log.warn("Could not list the active tenants to check the onboarding mode: {}",
                            e.getClass().getSimpleName());
                    return Mono.just(List.of());
                });
    }
}
