package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DeleteCredentialWorkflow}: owner-scoped lookup and session visibility. The deletion
 * itself is covered by {@link CredentialRemoverTest}.
 */
@ExtendWith(MockitoExtension.class)
class DeleteCredentialWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private PasskeyCustodyPolicy custodyPolicy;
    @Mock private CredentialRemover credentialRemover;

    private DeleteCredentialWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new DeleteCredentialWorkflow(credentialRepository, custodyPolicy, credentialRemover);
        lenient().when(custodyPolicy.visibleToSession(any(), any()))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));
    }

    @Nested
    @DisplayName("deleteCredential")
    class DeleteCredential {

        @Test
        @DisplayName("an owned credential is handed to the remover without extra audit data")
        void deleteCredential_ownedCredential_delegatesToTheRemover() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
            when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
            when(credentialRemover.remove(credential, Map.of())).thenReturn(Mono.empty());

            // Act
            var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(credentialRemover).remove(credential, Map.of());
        }

        @Test
        @DisplayName("a missing or not owned credential fails as not found without deleting")
        void deleteCredential_missingOrNotOwned_failsWithoutDeleting() {
            // Arrange
            when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.empty());

            // Act
            var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

            // Assert
            StepVerifier.create(result).expectError(CredentialNotFoundException.class).verify();
            verifyNoInteractions(credentialRemover);
        }

        @Test
        @DisplayName("a credential of another passkey with passkey custody fails as not found (EUD-11 FR-14)")
        void deleteCredential_credentialOfAnotherPasskeyWithPasskeyCustody_failsAsNotFound() {
            // Arrange
            var hidden = CredentialWorkflowFixtures.credential(USER_ID, true, UUID.randomUUID());
            when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(hidden));
            when(custodyPolicy.visibleToSession(hidden, PASSKEY_ID)).thenReturn(Mono.empty());

            // Act
            var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

            // Assert
            StepVerifier.create(result).expectError(CredentialNotFoundException.class).verify();
            verify(credentialRemover, never()).remove(any(), any());
        }

        @Test
        @DisplayName("a failing remover propagates the error")
        void deleteCredential_removerFails_propagatesTheError() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
            when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
            when(credentialRemover.remove(credential, Map.of())).thenReturn(Mono.error(new IllegalStateException("db down")));

            // Act
            var result = workflow.deleteCredential(USER_ID, PASSKEY_ID, CREDENTIAL_ID);

            // Assert
            StepVerifier.create(result).expectError(IllegalStateException.class).verify();
        }
    }
}
