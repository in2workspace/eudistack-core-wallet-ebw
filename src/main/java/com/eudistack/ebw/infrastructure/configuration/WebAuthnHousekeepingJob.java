package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.repository.RegistrationTicketRepository;
import com.eudistack.ebw.domain.repository.WebAuthnCeremonyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Every hour, deletes the WebAuthn ceremonies and registration tickets created more than one
 * day ago, in every active tenant schema (design AD-3). They are single use and expire after
 * 5 minutes; the day of margin keeps them for diagnosis.
 */
@Slf4j
@Component
@EnableScheduling
@ConditionalOnProperty(name = "ebw.webauthn.housekeeping.enabled", havingValue = "true", matchIfMissing = true)
public class WebAuthnHousekeepingJob {

    static final Duration RETENTION = Duration.ofDays(1);

    private final ActiveTenantDirectory tenantDirectory;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final RegistrationTicketRepository ticketRepository;

    public WebAuthnHousekeepingJob(ActiveTenantDirectory tenantDirectory,
                                   WebAuthnCeremonyRepository ceremonyRepository,
                                   RegistrationTicketRepository ticketRepository) {
        this.tenantDirectory = tenantDirectory;
        this.ceremonyRepository = ceremonyRepository;
        this.ticketRepository = ticketRepository;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void scheduledCleanup() {
        cleanup().subscribe();
    }

    /** Emits the number of deleted rows across all tenants. */
    public Mono<Long> cleanup() {
        var cutoff = Instant.now().minus(RETENTION);
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> ceremonyRepository.deleteCreatedBefore(cutoff)
                        .zipWith(ticketRepository.deleteCreatedBefore(cutoff), Long::sum)
                        .doOnNext(deleted -> log.debug("Deleted {} expired WebAuthn rows in tenant '{}'",
                                deleted, tenant))
                        .onErrorResume(e -> {
                            log.warn("WebAuthn housekeeping failed for tenant '{}': {}", tenant, e.getMessage());
                            return Mono.just(0L);
                        })
                        .contextWrite(ctx -> ctx.put(ReactorContextKeys.TENANT_DOMAIN, tenant)))
                .reduce(0L, Long::sum)
                .onErrorResume(e -> {
                    log.warn("WebAuthn housekeeping could not list the active tenants: {}", e.getMessage());
                    return Mono.just(0L);
                });
    }
}
