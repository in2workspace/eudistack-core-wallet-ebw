package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.ConfirmPasskeySessionWorkflow;
import com.eudistack.ebw.application.workflow.DeletePasskeyWorkflow;
import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow;
import com.eudistack.ebw.application.workflow.RegisterPasskeyWorkflow;
import com.eudistack.ebw.application.workflow.RevokePasskeySessionsWorkflow;
import com.eudistack.ebw.application.workflow.UpdatePasskeyWorkflow;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.infrastructure.controller.dto.ConfirmSessionRequest;
import com.eudistack.ebw.infrastructure.controller.dto.RegisterPasskeyRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the two {@link PasskeyController} endpoints touched by EUD-104
 * (session-to-passkey attribution): {@code register()}'s new {@code refreshToken}
 * pass-through, and the new {@code confirm-session} endpoint. Plain direct method
 * calls rather than {@code WebTestClient} — the HTTP-status contract for these two
 * endpoints (401/404/204/201) is already exercised end-to-end by
 * {@link com.eudistack.ebw.integration.PasskeyFlowIntegrationTest}; this class only
 * needs to prove the controller wires arguments to the right workflow.
 */
class PasskeyControllerTest {

    private RegisterPasskeyWorkflow registerPasskeyWorkflow;
    private ConfirmPasskeySessionWorkflow confirmPasskeySessionWorkflow;
    private PasskeyController controller;

    private UUID userId;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        registerPasskeyWorkflow = mock(RegisterPasskeyWorkflow.class);
        confirmPasskeySessionWorkflow = mock(ConfirmPasskeySessionWorkflow.class);
        controller = new PasskeyController(
                registerPasskeyWorkflow,
                mock(ListPasskeysWorkflow.class),
                mock(UpdatePasskeyWorkflow.class),
                mock(DeletePasskeyWorkflow.class),
                mock(RevokePasskeySessionsWorkflow.class),
                confirmPasskeySessionWorkflow);

        userId = UUID.randomUUID();
        auth = new JwtAuthenticationToken(userId, "user@example.com", List.of());
    }

    @Test
    void register_withRefreshToken_passesItThroughToTheWorkflow() {
        // Arrange
        var request = new RegisterPasskeyRequest("cred-1", "My PC", "ua", "raw-refresh-token");
        var created = UserPasskey.create(userId, "cred-1", "My PC", "ua");
        when(registerPasskeyWorkflow.registerPasskey(userId, "cred-1", "My PC", "ua", "raw-refresh-token"))
                .thenReturn(Mono.just(created));

        // Act
        var result = controller.register(request, auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> assertThat(response.credentialId()).isEqualTo("cred-1"))
                .verifyComplete();
        verify(registerPasskeyWorkflow).registerPasskey(userId, "cred-1", "My PC", "ua", "raw-refresh-token");
    }

    @Test
    void register_withoutRefreshToken_passesNullThrough() {
        // Arrange
        var request = new RegisterPasskeyRequest("cred-1", "My PC", "ua", null);
        var created = UserPasskey.create(userId, "cred-1", "My PC", "ua");
        when(registerPasskeyWorkflow.registerPasskey(eq(userId), eq("cred-1"), eq("My PC"), eq("ua"), any()))
                .thenReturn(Mono.just(created));

        // Act
        var result = controller.register(request, auth);

        // Assert
        StepVerifier.create(result).expectNextCount(1).verifyComplete();
        verify(registerPasskeyWorkflow).registerPasskey(userId, "cred-1", "My PC", "ua", null);
    }

    @Test
    void confirmSession_delegatesToTheWorkflowWithTheCallersUserId() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        var request = new ConfirmSessionRequest("raw-refresh-token");
        when(confirmPasskeySessionWorkflow.confirmSession(userId, passkeyId, "raw-refresh-token"))
                .thenReturn(Mono.empty());

        // Act
        var result = controller.confirmSession(passkeyId, request, auth);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(confirmPasskeySessionWorkflow).confirmSession(userId, passkeyId, "raw-refresh-token");
    }

    @Test
    void confirmSession_propagatesWorkflowErrors() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        var request = new ConfirmSessionRequest("raw-refresh-token");
        when(confirmPasskeySessionWorkflow.confirmSession(any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("not found")));

        // Act
        var result = controller.confirmSession(passkeyId, request, auth);

        // Assert
        StepVerifier.create(result)
                .expectErrorMessage("not found")
                .verify();
    }
}
