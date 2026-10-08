package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.LastPasskeyException;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DeletePasskeyWorkflow} — sessions revoked before the passkey is removed,
 * and the user's last passkey is never deletable.
 */
@ExtendWith(MockitoExtension.class)
class DeletePasskeyWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private AuditService auditService;

    private DeletePasskeyWorkflow workflow;
    private UserPasskey passkey;

    @BeforeEach
    void setUp() {
        workflow = new DeletePasskeyWorkflow(passkeyRepository, refreshTokenRepository, auditService);
        passkey = UserPasskey.create(USER_ID, "cred-1", "Office laptop", "ua");
    }

    @Test
    void deletePasskey_userHasOtherPasskeys_revokesSessionsDeletesAndAudits() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.just(passkey));
        when(passkeyRepository.countByUserId(USER_ID)).thenReturn(Mono.just(2L));
        when(refreshTokenRepository.revokeByPasskeyId(passkey.getId())).thenReturn(Mono.empty());
        when(passkeyRepository.deleteById(passkey.getId())).thenReturn(Mono.empty());
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.deletePasskey(USER_ID, passkey.getId());

        // Assert
        StepVerifier.create(result).verifyComplete();
        var order = inOrder(refreshTokenRepository, passkeyRepository, auditService);
        order.verify(refreshTokenRepository).revokeByPasskeyId(passkey.getId());
        order.verify(passkeyRepository).deleteById(passkey.getId());
        order.verify(auditService).record("passkey", passkey.getId(), "PASSKEY_DELETED", USER_ID,
                Map.of("display_name", "Office laptop"));
    }

    @Test
    void deletePasskey_lastPasskey_failsWithLastPasskeyAndKeepsIt() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.just(passkey));
        when(passkeyRepository.countByUserId(USER_ID)).thenReturn(Mono.just(1L));

        // Act
        var result = workflow.deletePasskey(USER_ID, passkey.getId());

        // Assert
        StepVerifier.create(result).expectError(LastPasskeyException.class).verify();
        verify(passkeyRepository, never()).deleteById(any());
        verifyNoInteractions(refreshTokenRepository, auditService);
    }

    @Test
    void deletePasskey_passkeyOfAnotherUser_failsWithPasskeyNotFound() {
        // Arrange
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.deletePasskey(USER_ID, passkey.getId());

        // Assert
        StepVerifier.create(result).expectError(PasskeyNotFoundException.class).verify();
        verify(passkeyRepository, never()).countByUserId(any());
    }
}
