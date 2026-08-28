package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.domain.repository.WalletActivityRepository;
import com.eudistack.ebw.domain.service.AuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RecordActivityWorkflow} — idempotent recording + audit trail (EUD-141).
 */
@ExtendWith(MockitoExtension.class)
class RecordActivityWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID ACTIVITY_ID = UUID.randomUUID();

    @Mock private WalletActivityRepository activityRepository;
    @Mock private AuditService auditService;

    private RecordActivityWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new RecordActivityWorkflow(activityRepository, auditService);
    }

    @Test
    void recordActivity_newEvent_persistsAndWritesAuditEntry() {
        when(activityRepository.insertIfAbsent(any(WalletActivity.class)))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0)));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.recordActivity(USER_ID, ACTIVITY_ID, ActivityType.ISSUED,
                        "LEARCredentialEmployee", "https://issuer.example.com",
                        "details", List.of("given_name")))
                .assertNext(activity -> {
                    assertThat(activity.getId()).isEqualTo(ACTIVITY_ID);
                    assertThat(activity.getUserId()).isEqualTo(USER_ID);
                    assertThat(activity.getType()).isEqualTo(ActivityType.ISSUED);
                })
                .verifyComplete();

        verify(auditService).record(eq("activity"), eq(ACTIVITY_ID), eq("ISSUED"), eq(USER_ID),
                eq(Map.of("credential_name", "LEARCredentialEmployee",
                        "counterparty", "https://issuer.example.com")));
    }

    @Test
    void recordActivity_idAlreadyExists_isIdempotentAndSkipsAudit() {
        // insertIfAbsent completes empty when a row with this id already exists (ON CONFLICT DO NOTHING).
        when(activityRepository.insertIfAbsent(any(WalletActivity.class))).thenReturn(Mono.empty());

        StepVerifier.create(workflow.recordActivity(USER_ID, ACTIVITY_ID, ActivityType.PRESENTED,
                        "LEARCredentialEmployee", "https://verifier.example.com", null, null))
                .assertNext(activity -> {
                    assertThat(activity.getId()).isEqualTo(ACTIVITY_ID);
                    assertThat(activity.getUserId()).isEqualTo(USER_ID);
                })
                .verifyComplete();

        verify(auditService, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    void recordActivity_sameEventReplayedTwice_secondCallIsNoOp() {
        when(activityRepository.insertIfAbsent(any(WalletActivity.class))).thenReturn(Mono.empty());

        // Simulates a device retrying (or a second device replaying) the same sync event.
        StepVerifier.create(workflow.recordActivity(USER_ID, ACTIVITY_ID, ActivityType.DELETED,
                        "cred", "n/a", null, null))
                .expectNextCount(1)
                .verifyComplete();
        StepVerifier.create(workflow.recordActivity(USER_ID, ACTIVITY_ID, ActivityType.DELETED,
                        "cred", "n/a", null, null))
                .expectNextCount(1)
                .verifyComplete();

        verify(auditService, never()).record(any(), any(), any(), any(), any());
    }
}
