package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.repository.TenantConfigRepository;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * At startup, after the tenant migrations, logs an ERROR for every active tenant without
 * {@code ebw.webauthn.rp_id}: those tenants cannot register passkeys nor sign in until it is
 * configured (design AD-5). Never blocks nor fails the startup.
 */
@Slf4j
@Component
@Order(2)
public class WebAuthnRelyingPartyStartupCheck implements ApplicationRunner {

    private final ActiveTenantDirectory tenantDirectory;
    private final TenantConfigRepository tenantConfigRepository;

    public WebAuthnRelyingPartyStartupCheck(ActiveTenantDirectory tenantDirectory,
                                            TenantConfigRepository tenantConfigRepository) {
        this.tenantDirectory = tenantDirectory;
        this.tenantConfigRepository = tenantConfigRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        tenantDirectory.activeTenants()
                .concatMap(tenant -> tenantConfigRepository.findByConfigKey(WalletAuthSettingsService.RP_ID)
                        .filter(config -> config.configValue() != null && !config.configValue().isBlank())
                        .hasElement()
                        .doOnNext(configured -> {
                            if (!configured) {
                                log.error("Tenant '{}' has no tenant_config '{}': passkey registration and "
                                        + "sign-in will fail for it", tenant, WalletAuthSettingsService.RP_ID);
                            }
                        })
                        .onErrorResume(e -> {
                            log.warn("Could not check '{}' for tenant '{}': {}", WalletAuthSettingsService.RP_ID,
                                    tenant, e.getMessage());
                            return Mono.empty();
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .onErrorResume(e -> {
                    log.warn("Could not list the active tenants to check the WebAuthn configuration: {}",
                            e.getMessage());
                    return Mono.empty();
                })
                .subscribe();
    }
}
