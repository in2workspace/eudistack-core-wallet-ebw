package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.model.exception.InvalidTransitionException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.UUID;

import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.credential;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UpdateCredentialStatusWorkflow} — ownership lookup, transition rules and audit.
 */
@ExtendWith(MockitoExtension.class)
class UpdateCredentialStatusWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;
    @Mock private AuditService auditService;

    private UpdateCredentialStatusWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new UpdateCredentialStatusWorkflow(credentialRepository, credentialService, auditService);
    }

    @Test
    void updateStatus_allowedTransition_updatesCredentialAndRecordsAudit() {
        // Arrange
        var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
        var previousUpdatedAt = credential.getUpdatedAt();
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
        when(credentialService.computeAuditHash("raw-credential")).thenReturn("hash");
        when(credentialRepository.update(credential)).thenReturn(Mono.just(credential));
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());

        // Act
        var result = workflow.updateStatus(USER_ID, CREDENTIAL_ID, "SUSPENDED");

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> {
                    assertThat(saved.getStatus()).isEqualTo(CredentialStatus.SUSPENDED);
                    assertThat(saved.getUpdatedAt()).isAfterOrEqualTo(previousUpdatedAt);
                })
                .verifyComplete();
        verify(credentialService).validateStatusTransition(CredentialStatus.VALID, CredentialStatus.SUSPENDED);
        verify(auditService).record("credential", CREDENTIAL_ID, "STATUS_CHANGED", USER_ID,
                Map.of("entity_hash", "sha256:hash", "old_status", "VALID", "new_status", "SUSPENDED"));
    }

    @Test
    void updateStatus_unknownStatusValue_failsWithIllegalArgumentWithoutLookup() {
        // Act
        var result = workflow.updateStatus(USER_ID, CREDENTIAL_ID, "ARCHIVED");

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("Invalid status: ARCHIVED"))
                .verify();
        verifyNoInteractions(credentialRepository, auditService);
    }

    @Test
    void updateStatus_credentialNotOwnedOrMissing_failsWithCredentialNotFound() {
        // Arrange
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.updateStatus(USER_ID, CREDENTIAL_ID, "REVOKED");

        // Assert
        StepVerifier.create(result)
                .expectError(CredentialNotFoundException.class)
                .verify();
        verify(credentialRepository, never()).update(any());
    }

    @Test
    void updateStatus_forbiddenTransition_failsWithoutPersistingOrAuditing() {
        // Arrange
        var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.REVOKED);
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
        doThrow(new InvalidTransitionException("REVOKED", "VALID"))
                .when(credentialService).validateStatusTransition(CredentialStatus.REVOKED, CredentialStatus.VALID);

        // Act
        var result = workflow.updateStatus(USER_ID, CREDENTIAL_ID, "VALID");

        // Assert
        StepVerifier.create(result)
                .expectError(InvalidTransitionException.class)
                .verify();
        assertThat(credential.getStatus()).isEqualTo(CredentialStatus.REVOKED);
        verify(credentialRepository, never()).update(any());
        verifyNoInteractions(auditService);
    }
}
