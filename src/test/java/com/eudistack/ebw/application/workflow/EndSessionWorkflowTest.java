package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link EndSessionWorkflow}. */
@ExtendWith(MockitoExtension.class)
class EndSessionWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID SESSION_ID = UUID.randomUUID();

    @Mock private AuthTokenService authTokenService;
    @Mock private AuditService auditService;

    private EndSessionWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new EndSessionWorkflow(authTokenService, auditService);
    }

    @Test
    void endCurrentSession_session_endsItAndAuditsSignOut() {
        // Arrange
        when(authTokenService.endSession(SESSION_ID)).thenReturn(Mono.empty());
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.endCurrentSession(USER_ID, SESSION_ID)).verifyComplete();
        verify(auditService).record("session", SESSION_ID, AuthAuditEvents.SESSION_ENDED, USER_ID,
                Map.of("reason", "sign_out"));
    }

    @Test
    void endOtherSessions_account_keepsTheCurrentAndAuditsTheCount() {
        // Arrange
        when(authTokenService.endOtherSessions(USER_ID, SESSION_ID)).thenReturn(Mono.just(3L));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.endOtherSessions(USER_ID, SESSION_ID)).verifyComplete();
        verify(auditService).record("user", USER_ID, AuthAuditEvents.OTHER_SESSIONS_ENDED, USER_ID,
                Map.of("kept_session_id", SESSION_ID.toString(), "revoked_tokens", 3L));
    }
}
