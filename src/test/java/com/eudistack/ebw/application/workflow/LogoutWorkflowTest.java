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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LogoutWorkflow} — global logout audited only when the token resolved to a user.
 */
@ExtendWith(MockitoExtension.class)
class LogoutWorkflowTest {

    private static final String RAW_TOKEN = "raw-refresh-token";

    @Mock private AuthTokenService authTokenService;
    @Mock private AuditService auditService;

    private LogoutWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new LogoutWorkflow(authTokenService, auditService);
    }

    @Test
    void logout_tokenOfAKnownUser_revokesAllSessionsAndRecordsAudit() {
        // Arrange
        var userId = UUID.randomUUID();
        when(authTokenService.revokeAllByRefreshToken(RAW_TOKEN)).thenReturn(Mono.just(userId));
        when(auditService.record("USER", userId, "LOGOUT", userId, Map.of("type", "global_logout")))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.logout(RAW_TOKEN);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(auditService).record("USER", userId, "LOGOUT", userId, Map.of("type", "global_logout"));
    }

    @Test
    void logout_unknownToken_completesWithoutAudit() {
        // Arrange
        when(authTokenService.revokeAllByRefreshToken(RAW_TOKEN)).thenReturn(Mono.empty());

        // Act
        var result = workflow.logout(RAW_TOKEN);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verifyNoInteractions(auditService);
    }
}
