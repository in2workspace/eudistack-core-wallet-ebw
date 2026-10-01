package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RevokePasskeySessionsWorkflowTest {

    private UserPasskeyRepository passkeyRepository;
    private AuthTokenService authTokenService;
    private AuditService auditService;
    private RevokePasskeySessionsWorkflow workflow;

    private UUID userId;
    private UUID passkeyId;

    @BeforeEach
    void setUp() {
        passkeyRepository = mock(UserPasskeyRepository.class);
        authTokenService = mock(AuthTokenService.class);
        auditService = mock(AuditService.class);
        workflow = new RevokePasskeySessionsWorkflow(passkeyRepository, authTokenService, auditService);

        userId = UUID.randomUUID();
        passkeyId = UUID.randomUUID();
    }

    @Test
    void revokeSessions_ownedPasskey_revokesViaAuthTokenServiceAndAudits() {
        // Arrange
        var passkey = new UserPasskey(passkeyId, userId, "cred", "My Laptop", "UA", Instant.now(), Instant.now());
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.just(passkey));
        when(authTokenService.revokeAllByPasskey(passkeyId)).thenReturn(Mono.empty());
        when(auditService.record(eq("passkey"), eq(passkeyId), eq("SESSIONS_REVOKED"), eq(userId), any()))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.revokeSessions(userId, passkeyId);

        // Assert — must go through AuthTokenService (which also invalidates the
        // session-revocation cache), never straight to the repository.
        StepVerifier.create(result).verifyComplete();
        verify(authTokenService).revokeAllByPasskey(passkeyId);
        verify(auditService).record("passkey", passkeyId, "SESSIONS_REVOKED", userId, Map.of());
    }

    @Test
    void revokeSessions_unknownOrNotOwnedPasskey_throwsNotFound() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.empty());

        // Act
        var result = workflow.revokeSessions(userId, passkeyId);

        // Assert
        StepVerifier.create(result)
                .expectError(PasskeyNotFoundException.class)
                .verify();
        verify(authTokenService, never()).revokeAllByPasskey(any());
    }
}
