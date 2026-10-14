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

import java.util.List;

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
        tenantsWithoutRelyingParty().subscribe();
    }

    /** Emits the active tenants without {@code ebw.webauthn.rp_id}, each logged as ERROR. */
    public Mono<List<String>> tenantsWithoutRelyingParty() {
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> tenantConfigRepository.findByConfigKey(WalletAuthSettingsService.RP_ID)
                        .filter(config -> config.configValue() != null && !config.configValue().isBlank())
                        .hasElement()
                        .filter(configured -> !configured)
                        .map(missing -> {
                            log.error("Tenant '{}' has no tenant_config '{}': passkey registration and "
                                    + "sign-in will fail for it", tenant, WalletAuthSettingsService.RP_ID);
                            return tenant;
                        })
                        .onErrorResume(e -> {
                            log.warn("Could not check '{}' for tenant '{}': {}", WalletAuthSettingsService.RP_ID,
                                    tenant, e.getClass().getSimpleName());
                            return Mono.empty();
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .collectList()
                .onErrorResume(e -> {
                    log.warn("Could not list the active tenants to check the WebAuthn configuration: {}",
                            e.getClass().getSimpleName());
                    return Mono.just(List.of());
                });
    }
}
