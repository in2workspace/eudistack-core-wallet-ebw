package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.LastPasskeyException;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.AuthTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DeletePasskeyWorkflowTest {

    private UserPasskeyRepository passkeyRepository;
    private AuthTokenService authTokenService;
    private AuditService auditService;
    private DeletePasskeyWorkflow workflow;

    private UUID userId;
    private UUID passkeyId;
    private UserPasskey passkey;

    @BeforeEach
    void setUp() {
        passkeyRepository = mock(UserPasskeyRepository.class);
        authTokenService = mock(AuthTokenService.class);
        auditService = mock(AuditService.class);
        workflow = new DeletePasskeyWorkflow(passkeyRepository, authTokenService, auditService);

        userId = UUID.randomUUID();
        passkeyId = UUID.randomUUID();
        passkey = new UserPasskey(passkeyId, userId, "cred", "My Laptop", "UA", Instant.now(), Instant.now());
    }

    @Test
    void deletePasskey_notTheLastOne_revokesSessionsThenDeletes() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.just(passkey));
        when(passkeyRepository.countByUserId(userId)).thenReturn(Mono.just(2L));
        when(authTokenService.revokeAllByPasskey(passkeyId)).thenReturn(Mono.empty());
        when(passkeyRepository.deleteById(passkeyId)).thenReturn(Mono.empty());
        when(auditService.record(eq("passkey"), eq(passkeyId), eq("PASSKEY_DELETED"), eq(userId), any()))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.deletePasskey(userId, passkeyId);

        // Assert — sessions must be revoked (via AuthTokenService, which also invalidates
        // the session-revocation cache) before the passkey row disappears.
        StepVerifier.create(result).verifyComplete();
        verify(authTokenService).revokeAllByPasskey(passkeyId);
        verify(passkeyRepository).deleteById(passkeyId);
    }

    @Test
    void deletePasskey_lastRemainingOne_throwsLastPasskeyExceptionWithoutRevokingOrDeleting() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.just(passkey));
        when(passkeyRepository.countByUserId(userId)).thenReturn(Mono.just(1L));

        // Act
        var result = workflow.deletePasskey(userId, passkeyId);

        // Assert
        StepVerifier.create(result)
                .expectError(LastPasskeyException.class)
                .verify();
        verify(authTokenService, never()).revokeAllByPasskey(any());
        verify(passkeyRepository, never()).deleteById(any());
    }

    @Test
    void deletePasskey_unknownOrNotOwnedPasskey_throwsNotFound() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkeyId, userId)).thenReturn(Mono.empty());

        // Act
        var result = workflow.deletePasskey(userId, passkeyId);

        // Assert
        StepVerifier.create(result)
                .expectError(PasskeyNotFoundException.class)
                .verify();
        verify(authTokenService, never()).revokeAllByPasskey(any());
    }
}
