package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;

/**
 * Hourly cleanup of the onboarding ticket data of the current tenant (design §2.6, FR-25, AC-05,
 * EC-12): physically deletes the expired pre-registrations, with their email, and traces each one
 * as {@code PREREGISTRATION_EXPIRED}, redeemed or not: a pre-registration that reaches its expiry
 * is an onboarding never completed (the completed ones are deleted before). Then deletes the
 * "it was not me" tokens already used or expired.
 */
@Service
public class ExpireOnboardingWorkflow {

    private final OnboardingPreregistrationRepository preregistrationRepository;
    private final OnboardingDisavowalRepository disavowalRepository;
    private final AuditService auditService;

    public ExpireOnboardingWorkflow(OnboardingPreregistrationRepository preregistrationRepository,
                                    OnboardingDisavowalRepository disavowalRepository, AuditService auditService) {
        this.preregistrationRepository = preregistrationRepository;
        this.disavowalRepository = disavowalRepository;
        this.auditService = auditService;
    }

    /** Emits the number of deleted rows (pre-registrations and "it was not me" tokens). */
    public Mono<Long> expire() {
        return preregistrationRepository.deleteExpired()
                .concatMap(expired -> trace(expired).thenReturn(1L))
                .reduce(0L, Long::sum)
                .zipWith(disavowalRepository.deleteConsumedOrExpired().defaultIfEmpty(0L), Long::sum);
    }

    private Mono<Void> trace(ExpiredPreregistration expired) {
        return auditService.record(AuthAuditEvents.ENTITY_PREREGISTRATION, expired.id(),
                AuthAuditEvents.PREREGISTRATION_EXPIRED, null,
                Map.of("requested_by", Objects.requireNonNullElse(expired.requestedBy(), "unknown"),
                        "redeemed", expired.redeemed()));
    }
}
