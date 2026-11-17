package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;

/**
 * Hourly cleanup of the onboarding ticket data of the current tenant (design §2.6, FR-25, AC-05,
 * EC-12, NFR-5): physically deletes the expired pre-registrations, with their email, and traces each
 * one as {@code PREREGISTRATION_EXPIRED}, redeemed or not: a pre-registration that reaches its expiry
 * is an onboarding never completed (the completed ones are deleted before). Then deletes the
 * "it was not me" tokens already used or expired.
 *
 * <p>The deletion of the pre-registrations and their traces run in one transaction: if a trace
 * cannot be written, nothing is deleted and the next pass tries again, so no pre-registration
 * disappears without its trace. The two steps are independent: a failure in one never keeps the
 * other from running.
 */
@Slf4j
@Service
public class ExpireOnboardingWorkflow {

    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final OnboardingDisavowalRepository disavowalRepository;
    private final AuditService auditService;
    private final TransactionRunner transactionRunner;

    public ExpireOnboardingWorkflow(OnboardingPreregistrationRepository preregistrationRepository,
                                    OnboardingDisavowalRepository disavowalRepository, AuditService auditService,
                                    TransactionRunner transactionRunner) {
        this.preregistrationRepository = preregistrationRepository;
        this.disavowalRepository = disavowalRepository;
        this.auditService = auditService;
        this.transactionRunner = transactionRunner;
    }

    /**
     * Emits the number of deleted rows (pre-registrations and "it was not me" tokens). A step that
     * fails counts 0 and is logged; the other still runs.
     */
    public Mono<Long> expire() {
        return expirePreregistrations()
                .onErrorResume(e -> {
                    log.warn("Expired pre-registrations not deleted: {}", e.getClass().getSimpleName());
                    return Mono.just(0L);
                })
                .flatMap(preregistrations -> deleteUsedDisavowals()
                        .onErrorResume(e -> {
                            log.warn("Used \"it was not me\" tokens not deleted: {}", e.getClass().getSimpleName());
                            return Mono.just(0L);
                        })
                        .map(disavowals -> preregistrations + disavowals));
    }

    /** Deletes the expired pre-registrations and traces each one, all or nothing. */
    Mono<Long> expirePreregistrations() {
        return transactionRunner.inTransaction(preregistrationRepository.deleteExpired()
                .concatMap(expired -> trace(expired).thenReturn(1L))
                .reduce(0L, Long::sum));
    }

    private Mono<Long> deleteUsedDisavowals() {
        return disavowalRepository.deleteConsumedOrExpired().defaultIfEmpty(0L);
    }

    private Mono<Void> trace(ExpiredPreregistration expired) {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, expired.id(),
                AuthAuditEvents.PREREGISTRATION_EXPIRED, null,
                Map.of("requested_by", Objects.requireNonNullElse(expired.requestedBy(), "unknown"),
                        "redeemed", expired.redeemed()));
    }
}
