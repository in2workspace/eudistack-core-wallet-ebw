package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ConfirmPasskeySessionWorkflowTest {

    private UserPasskeyRepository passkeyRepository;
    private AuthTokenService authTokenService;
    private ConfirmPasskeySessionWorkflow workflow;

    private UUID userId;
    private UUID passkeyId;

    @BeforeEach
    void setUp() {
        passkeyRepository = mock(UserPasskeyRepository.class);
        authTokenService = mock(AuthTokenService.class);
        workflow = new ConfirmPasskeySessionWorkflow(passkeyRepository, authTokenService);

        userId = UUID.randomUUID();
        passkeyId = UUID.randomUUID();
    }

    @Test
    void confirmSession_passkeyOwnedByCaller_linksSessionToIt() {
        // Arrange
        var passkey = UserPasskey.create(userId, "cred-1", "My PC", "ua");
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.just(passkey));
        when(authTokenService.linkSessionToPasskey("raw-token", userId, passkey.getId())).thenReturn(Mono.empty());

        // Act
        var result = workflow.confirmSession(userId, passkeyId, "raw-token");

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
        verify(authTokenService).linkSessionToPasskey("raw-token", userId, passkey.getId());
    }

    @Test
    void confirmSession_passkeyNotFoundForCaller_throwsPasskeyNotFoundException() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.empty());

        // Act
        var result = workflow.confirmSession(userId, passkeyId, "raw-token");

        // Assert
        StepVerifier.create(result)
                .expectError(PasskeyNotFoundException.class)
                .verify();
        verify(authTokenService, never()).linkSessionToPasskey(any(), any(), any());
    }
}
