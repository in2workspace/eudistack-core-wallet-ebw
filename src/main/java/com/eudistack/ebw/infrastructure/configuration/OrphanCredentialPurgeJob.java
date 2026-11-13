package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.application.workflow.PurgeOrphanCredentialsWorkflow;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Once a day, in every active tenant, deletes the expired orphan attestations of the tenants with passkey
 * custody. A tenant that fails is logged and the others still run.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OrphanCredentialPurgeJob {

    private final ActiveTenantDirectory tenantDirectory;
    private final PurgeOrphanCredentialsWorkflow purgeWorkflow;

    @Scheduled(cron = "0 30 3 * * *")
    public void scheduledPurge() {
        purge().subscribe();
    }

    /** Emits the number of attestations deleted across all tenants. */
    public Mono<Long> purge() {
        var now = Instant.now();
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> purgeWorkflow.purgeExpiredOrphans(now)
                        .doOnNext(deleted -> {
                            if (deleted > 0) {
                                log.info("Purged {} expired orphan credentials in tenant '{}'", deleted, tenant);
                            } else {
                                log.debug("No expired orphan credentials to purge in tenant '{}'", tenant);
                            }
                        })
                        .onErrorResume(e -> {
                            log.warn("Orphan credential purge failed for tenant '{}': {}", tenant, e.getMessage());
                            return Mono.just(0L);
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .reduce(0L, Long::sum)
                .onErrorResume(e -> {
                    log.warn("Orphan credential purge could not list the active tenants: {}", e.getMessage());
                    return Mono.just(0L);
                });
    }
}
