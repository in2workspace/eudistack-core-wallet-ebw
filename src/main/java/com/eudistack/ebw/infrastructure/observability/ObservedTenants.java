package com.eudistack.ebw.infrastructure.observability;

import com.eudistack.ebw.infrastructure.configuration.ActiveTenantDirectory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The value of the {@code tenant} tag on spans and metrics: the tenant itself when it is active in
 * {@code public.tenant_registry}, {@value #UNKNOWN_TENANT} otherwise. The request filter only checks
 * the shape of the tenant, and every distinct value creates new metric series, so an invented
 * subdomain must not become a tag. The request itself is not affected.
 *
 * <p>Loaded when the application is ready and refreshed every 5 minutes, as {@code TenantOrigins}
 * does; until then every tenant is {@value #UNKNOWN_TENANT}. If the active tenants cannot be listed,
 * the previous list stays. The directory is resolved lazily: this bean feeds the observation
 * filter, which the observation registry needs before the database client exists.
 */
@Slf4j
@Component
@EnableScheduling
public class ObservedTenants {

    public static final String UNKNOWN_TENANT = "unknown";

    private final ObjectProvider<ActiveTenantDirectory> tenantDirectory;
    /** Always an immutable set, replaced whole on each refresh. */
    private final AtomicReference<Set<String>> activeTenants = new AtomicReference<>(Set.of());

    public ObservedTenants(ObjectProvider<ActiveTenantDirectory> tenantDirectory) {
        this.tenantDirectory = tenantDirectory;
    }

    /** The tag value for a resolved tenant, which may be {@code null}. */
    public String tagValue(String tenant) {
        return tenant != null && activeTenants.get().contains(tenant) ? tenant : UNKNOWN_TENANT;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        refresh().subscribe();
    }

    @Scheduled(fixedDelayString = "PT5M", initialDelayString = "PT5M")
    public void scheduledRefresh() {
        refresh().subscribe();
    }

    /** Emits the number of active tenants loaded, or the current number if they cannot be listed. */
    public Mono<Integer> refresh() {
        return tenantDirectory.getObject().activeTenants()
                .collectList()
                .map(tenants -> {
                    Set<String> loaded = Set.copyOf(tenants);
                    activeTenants.set(loaded);
                    return loaded.size();
                })
                .onErrorResume(e -> {
                    log.warn("Could not list the active tenants for the tenant tag: {}", e.getMessage());
                    return Mono.just(activeTenants.get().size());
                });
    }
}
