package com.eudistack.ebw.infrastructure.security;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.service.WalletAuthSettingsService;
import com.eudistack.ebw.infrastructure.configuration.ActiveTenantDirectory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Wallet App origins of every active tenant, for {@link TenantCorsConfigurationSource}, which
 * is synchronous. Loaded when the application is ready and refreshed every 5 minutes, so a change
 * of {@code ebw.webauthn.origins} or a new tenant is admitted within that time. A tenant that
 * cannot be read keeps its previous origins.
 */
@Slf4j
@Component
@EnableScheduling
public class TenantOrigins {

    private final ActiveTenantDirectory tenantDirectory;
    private final WalletAuthSettingsService settingsService;
    private final Map<String, List<String>> originsByTenant = new ConcurrentHashMap<>();

    public TenantOrigins(ActiveTenantDirectory tenantDirectory, WalletAuthSettingsService settingsService) {
        this.tenantDirectory = tenantDirectory;
        this.settingsService = settingsService;
    }

    public List<String> originsOf(String tenant) {
        return originsByTenant.getOrDefault(tenant, List.of());
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        refresh().subscribe();
    }

    @Scheduled(fixedDelayString = "PT5M", initialDelayString = "PT5M")
    public void scheduledRefresh() {
        refresh().subscribe();
    }

    /** Emits the number of tenants whose origins were loaded. */
    public Mono<Integer> refresh() {
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> settingsService.relyingParty()
                        .map(relyingParty -> Map.entry(tenant, relyingParty.origins()))
                        .onErrorResume(e -> {
                            log.warn("Could not load the CORS origins of tenant '{}': {}", tenant,
                                    e.getClass().getSimpleName());
                            return Mono.empty();
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .collectList()
                .map(entries -> {
                    entries.forEach(entry -> originsByTenant.put(entry.getKey(), List.copyOf(entry.getValue())));
                    return entries.size();
                })
                .onErrorResume(e -> {
                    log.warn("Could not list the active tenants to load their CORS origins: {}", e.getMessage());
                    return Mono.just(0);
                });
    }
}
