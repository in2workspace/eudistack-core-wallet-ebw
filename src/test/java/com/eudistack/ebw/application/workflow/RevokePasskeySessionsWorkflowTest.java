package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import com.eudistack.ebw.domain.service.AuditService;
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
 * Unit tests for {@link RevokePasskeySessionsWorkflow} — revokes one device's sessions, owner-scoped.
 */
@ExtendWith(MockitoExtension.class)
class RevokePasskeySessionsWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private AuditService auditService;

    private RevokePasskeySessionsWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new RevokePasskeySessionsWorkflow(passkeyRepository, refreshTokenRepository, auditService);
    }

    @Test
    void revokeSessions_ownedPasskey_revokesItsTokensAndAudits() {
        // Arrange
        var passkey = UserPasskey.create(USER_ID, "cred-1", "Phone", "ua");
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.just(passkey));
        when(refreshTokenRepository.revokeByPasskeyId(passkey.getId())).thenReturn(Mono.empty());
        when(auditService.record("passkey", passkey.getId(), "SESSIONS_REVOKED", USER_ID, Map.of()))
                .thenReturn(Mono.empty());

        // Act
        var result = workflow.revokeSessions(USER_ID, passkey.getId());

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(refreshTokenRepository).revokeByPasskeyId(passkey.getId());
        verify(auditService).record("passkey", passkey.getId(), "SESSIONS_REVOKED", USER_ID, Map.of());
    }

    @Test
    void revokeSessions_missingOrNotOwned_failsWithPasskeyNotFound() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        when(passkeyRepository.findByIdAndUserId(passkeyId, USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.revokeSessions(USER_ID, passkeyId);

        // Assert
        StepVerifier.create(result).expectError(PasskeyNotFoundException.class).verify();
        verifyNoInteractions(refreshTokenRepository, auditService);
    }
}
