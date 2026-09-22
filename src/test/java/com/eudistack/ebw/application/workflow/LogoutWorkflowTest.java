package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LogoutWorkflowTest {

    private AuthTokenService authTokenService;
    private AuditService auditService;
    private LogoutWorkflow workflow;

    private UUID userId;

    @BeforeEach
    void setUp() {
        authTokenService = mock(AuthTokenService.class);
        auditService = mock(AuditService.class);
        workflow = new LogoutWorkflow(authTokenService, auditService);

        userId = UUID.randomUUID();
    }

    @Test
    void logout_validToken_revokesOnlyThatDeviceAndAudits() {
        // Arrange
        when(authTokenService.revokeRefreshToken("raw-token")).thenReturn(Mono.just(userId));
        when(auditService.record(eq("USER"), eq(userId), eq("LOGOUT"), eq(userId), any()))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.logout("raw-token");

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(authTokenService).revokeRefreshToken("raw-token");
        verify(auditService).record("USER", userId, "LOGOUT", userId,
                Map.of("type", "device_logout"));
    }

    @Test
    void logout_unknownToken_completesWithoutAuditing() {
        // Arrange: idempotent — an already-revoked or unknown token must not fail logout.
        when(authTokenService.revokeRefreshToken("unknown-token")).thenReturn(Mono.empty());

        // Act
        var result = workflow.logout("unknown-token");

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(auditService, never()).record(any(), any(), any(), any(), any());
    }
}
