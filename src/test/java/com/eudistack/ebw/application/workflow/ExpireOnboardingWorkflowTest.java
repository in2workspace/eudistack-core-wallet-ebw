package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ExpiredPreregistration;
import com.eudistack.ebw.domain.repository.OnboardingDisavowalRepository;
import com.eudistack.ebw.domain.repository.OnboardingPreregistrationRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.spi.TransactionRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ExpireOnboardingWorkflow} (AC-05, EC-12, FR-25, NFR-5). */
@ExtendWith(MockitoExtension.class)
class ExpireOnboardingWorkflowTest {

    @Mock private OnboardingPreregistrationRepository preregistrationRepository;
    @Mock private OnboardingDisavowalRepository disavowalRepository;
    @Mock private AuditService auditService;
    @Mock private TransactionRunner transactionRunner;

    private ExpireOnboardingWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ExpireOnboardingWorkflow(preregistrationRepository, disavowalRepository, auditService,
                transactionRunner);
        lenient().when(auditService.record(anyString(), any(), anyString(), any(), any())).thenReturn(Mono.empty());
        lenient().when(disavowalRepository.deleteConsumedOrExpired()).thenReturn(Mono.just(0L));
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void expire_preregistrationsAndTheirTraces_runInOneTransaction() {
        // Arrange: AC-05, no pre-registration is deleted without its trace
        when(preregistrationRepository.deleteExpired()).thenReturn(Flux.empty());

        // Act
        StepVerifier.create(workflow.expire()).expectNext(0L).verifyComplete();

        // Assert
        verify(transactionRunner).inTransaction(any());
    }

    @Test
    void expire_traceFails_countsNoPreregistrationAndStillDeletesTheDisavowalTokens() {
        // Arrange: the transaction rolls the deletion back; the next pass tries again
        var expired = new ExpiredPreregistration(UUID.randomUUID(), "portal-machine.example.org", false);
        when(preregistrationRepository.deleteExpired()).thenReturn(Flux.just(expired));
        when(auditService.record(anyString(), any(), anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("audit down")));
        when(disavowalRepository.deleteConsumedOrExpired()).thenReturn(Mono.just(2L));

        // Act + Assert
        StepVerifier.create(workflow.expire()).expectNext(2L).verifyComplete();
    }

    @Test
    void expire_disavowalDeletionFails_stillCountsThePreregistrations() {
        // Arrange
        var expired = new ExpiredPreregistration(UUID.randomUUID(), "portal-machine.example.org", true);
        when(preregistrationRepository.deleteExpired()).thenReturn(Flux.just(expired));
        when(disavowalRepository.deleteConsumedOrExpired()).thenReturn(Mono.error(new IllegalStateException("db")));

        // Act + Assert
        StepVerifier.create(workflow.expire()).expectNext(1L).verifyComplete();
    }

    @Test
    void expire_expiredPreregistrations_areTracedRedeemedOrNot() {
        // Arrange: AC-05, a redeemed and abandoned onboarding is traced too
        var redeemed = new ExpiredPreregistration(UUID.randomUUID(), "portal-machine.example.org", true);
        var unredeemed = new ExpiredPreregistration(UUID.randomUUID(), "portal-machine.example.org", false);
        when(preregistrationRepository.deleteExpired()).thenReturn(Flux.just(redeemed, unredeemed));

        // Act + Assert
        StepVerifier.create(workflow.expire()).expectNext(2L).verifyComplete();
        verify(auditService).record(eq("onboarding_preregistration"), eq(redeemed.id()),
                eq(AuthAuditEvents.PREREGISTRATION_EXPIRED), isNull(),
                eq(Map.of("requested_by", "portal-machine.example.org", "redeemed", true)));
        verify(auditService).record(eq("onboarding_preregistration"), eq(unredeemed.id()),
                eq(AuthAuditEvents.PREREGISTRATION_EXPIRED), isNull(),
                eq(Map.of("requested_by", "portal-machine.example.org", "redeemed", false)));
    }

    @Test
    void expire_disavowalTokens_usedOrExpiredAreDeletedAndCounted() {
        // Arrange: EC-12
        when(preregistrationRepository.deleteExpired()).thenReturn(Flux.empty());
        when(disavowalRepository.deleteConsumedOrExpired()).thenReturn(Mono.just(3L));

        // Act + Assert
        StepVerifier.create(workflow.expire()).expectNext(3L).verifyComplete();
        verify(auditService, never()).record(anyString(), any(), anyString(), any(), any());
    }
}
