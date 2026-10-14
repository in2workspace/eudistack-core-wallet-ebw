package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DeleteCredentialWorkflow} — owner-scoped delete, audited before the row is removed.
 */
@ExtendWith(MockitoExtension.class)
class DeleteCredentialWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;
    @Mock private AuditService auditService;
    @Mock private PasskeyCustodyPolicy custodyPolicy;

    private DeleteCredentialWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new DeleteCredentialWorkflow(credentialRepository, credentialService, auditService, custodyPolicy);
        org.mockito.Mockito.lenient().when(custodyPolicy.visibleToSession(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));
    }

    @Test
    void deleteCredential_ownedCredential_recordsAuditThenDeletes() {
        // Arrange
        var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.SUSPENDED);
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
        when(credentialService.computeAuditHash("raw-credential")).thenReturn("hash");
        when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(credentialRepository.deleteById(CREDENTIAL_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result).verifyComplete();
        var order = inOrder(auditService, credentialRepository);
        order.verify(auditService).record("credential", CREDENTIAL_ID, "DELETED", USER_ID,
                Map.of("entity_hash", "sha256:hash",
                        "credential_type", "LEARCredentialEmployee",
                        "issuer", "https://issuer",
                        "format", "dc+sd-jwt",
                        "previous_status", "SUSPENDED"));
        order.verify(credentialRepository).deleteById(CREDENTIAL_ID);
    }

    @Test
    void deleteCredential_missingOrNotOwned_failsWithoutDeleting() {
        // Arrange
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result)
                .expectError(CredentialNotFoundException.class)
                .verify();
        verify(credentialRepository, never()).deleteById(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void deleteCredential_credentialOfAnotherPasskeyWithPasskeyCustody_failsAsNotFound() {
        // Arrange — EUD-11 FR-14
        var hidden = CredentialWorkflowFixtures.credential(USER_ID, true, java.util.UUID.randomUUID());
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(hidden));
        when(custodyPolicy.visibleToSession(hidden, PASSKEY_ID)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID))
                .expectError(com.eudistack.ebw.domain.model.exception.CredentialNotFoundException.class)
                .verify();
        org.mockito.Mockito.verify(credentialRepository, org.mockito.Mockito.never()).deleteById(org.mockito.ArgumentMatchers.any());
    }
}
