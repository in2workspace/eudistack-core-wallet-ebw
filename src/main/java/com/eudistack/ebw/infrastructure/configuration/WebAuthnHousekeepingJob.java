package com.eudistack.ebw.infrastructure.configuration;

import com.eudistack.ebw.application.workflow.ExpireSessionsWorkflow;
import com.eudistack.ebw.domain.model.ReactorContextKeys;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
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
 * Every hour, in every active tenant schema: first closes and audits the sessions that lapsed
 * without anyone renewing or ending them ({@link ExpireSessionsWorkflow}, FR-22); then deletes the
 * WebAuthn ceremonies and registration tickets created more than one day ago (design AD-3; they
 * are single use and expire after 5 minutes, the day of margin keeps them for diagnosis), and the
 * refresh tokens of the sessions that ended more than {@link #ENDED_SESSION_RETENTION} ago. If the
 * expiry step fails, the tenant's deletions wait for the next pass, so no lapsed session is
 * deleted before it is audited.
 */
@Slf4j
@Component
@EnableScheduling
@ConditionalOnProperty(name = "ebw.webauthn.housekeeping.enabled", havingValue = "true", matchIfMissing = true)
public class WebAuthnHousekeepingJob {

    static final Duration RETENTION = Duration.ofDays(1);
    static final Duration ENDED_SESSION_RETENTION = Duration.ofDays(7);

    private final ActiveTenantDirectory tenantDirectory;
    private final ExpireSessionsWorkflow expireSessionsWorkflow;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final RegistrationTicketRepository ticketRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public WebAuthnHousekeepingJob(ActiveTenantDirectory tenantDirectory,
                                   ExpireSessionsWorkflow expireSessionsWorkflow,
                                   WebAuthnCeremonyRepository ceremonyRepository,
                                   RegistrationTicketRepository ticketRepository,
                                   RefreshTokenRepository refreshTokenRepository) {
        this.tenantDirectory = tenantDirectory;
        this.expireSessionsWorkflow = expireSessionsWorkflow;
        this.ceremonyRepository = ceremonyRepository;
        this.ticketRepository = ticketRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void scheduledCleanup() {
        cleanup().subscribe();
    }

    /** Emits the number of deleted rows across all tenants (the expired sessions are not counted). */
    public Mono<Long> cleanup() {
        var now = Instant.now();
        var cutoff = now.minus(RETENTION);
        var sessionCutoff = now.minus(ENDED_SESSION_RETENTION);
        return tenantDirectory.activeTenants()
                .concatMap(tenant -> expireSessionsWorkflow.expireLapsedSessions()
                        .doOnNext(expired -> log.debug("Expired {} lapsed sessions in tenant '{}'", expired, tenant))
                        .then(Mono.defer(() -> deleteExpiredRows(cutoff, sessionCutoff)))
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

    /** Runs after the expiry step, so no lapsed session is deleted before it is audited. */
    private Mono<Long> deleteExpiredRows(Instant cutoff, Instant sessionCutoff) {
        return ceremonyRepository.deleteCreatedBefore(cutoff)
                .zipWith(ticketRepository.deleteCreatedBefore(cutoff), Long::sum)
                .zipWith(refreshTokenRepository.deleteSessionsEndedBefore(sessionCutoff), Long::sum);
    }
}
