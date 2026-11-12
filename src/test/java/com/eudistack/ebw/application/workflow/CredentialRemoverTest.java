package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.AuditService;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.domain.spi.HolderKeyMaterialPort;
import com.eudistack.ebw.domain.spi.TransactionRunner;
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
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CredentialRemover}: key material and row deleted in one transaction, audited after it.
 */
@ExtendWith(MockitoExtension.class)
class CredentialRemoverTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;
    @Mock private AuditService auditService;
    @Mock private HolderKeyMaterialPort holderKeyMaterial;
    @Mock private TransactionRunner transactionRunner;

    private CredentialRemover remover;

    @BeforeEach
    void setUp() {
        remover = new CredentialRemover(credentialRepository, credentialService, auditService, holderKeyMaterial,
                transactionRunner);
        lenient().when(holderKeyMaterial.delete(any())).thenReturn(Mono.empty());
        lenient().when(transactionRunner.inTransaction(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(credentialService.computeAuditHash("raw-credential")).thenReturn("hash");
        lenient().when(credentialRepository.deleteById(CREDENTIAL_ID)).thenReturn(Mono.empty());
        lenient().when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.empty());
    }

    @Nested
    @DisplayName("remove")
    class Remove {

        @Test
        @DisplayName("deletes the row and then records DELETED with the fingerprint and the previous status")
        void remove_credential_deletesThenRecordsAudit() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.REVOKED);

            // Act
            var result = remover.remove(credential, USER_ID, Map.of());

            // Assert
            StepVerifier.create(result).verifyComplete();
            var order = inOrder(credentialRepository, auditService);
            order.verify(credentialRepository).deleteById(CREDENTIAL_ID);
            order.verify(auditService).record("credential", CREDENTIAL_ID, "DELETED", USER_ID,
                    Map.of("entity_hash", "sha256:hash",
                            "credential_type", "LEARCredentialEmployee",
                            "issuer", "https://issuer",
                            "format", "dc+sd-jwt",
                            "previous_status", "REVOKED"));
        }

        @Test
        @DisplayName("adds the extra audit metadata to the entry")
        void remove_withExtraAuditMetadata_includesItInTheEntry() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);

            // Act
            var result = remover.remove(credential, null, Map.of("reason", "orphan_expired"));

            // Assert
            StepVerifier.create(result).verifyComplete();
            verify(auditService).record("credential", CREDENTIAL_ID, "DELETED", null,
                    Map.of("reason", "orphan_expired",
                            "entity_hash", "sha256:hash",
                            "credential_type", "LEARCredentialEmployee",
                            "issuer", "https://issuer",
                            "format", "dc+sd-jwt",
                            "previous_status", "VALID"));
        }

        @Test
        @DisplayName("records the audit entry inside the same transaction as the deletion")
        void remove_credential_auditsInsideTheTransaction() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
            var inTransaction = new java.util.concurrent.atomic.AtomicBoolean(false);
            when(transactionRunner.inTransaction(any())).thenAnswer(inv -> {
                Mono<?> body = inv.getArgument(0);
                return Mono.defer(() -> {
                    inTransaction.set(true);
                    return body.doFinally(signal -> inTransaction.set(false));
                });
            });
            var auditedInsideTransaction = new java.util.concurrent.atomic.AtomicBoolean(false);
            when(auditService.record(any(), any(), any(), any(), any())).thenAnswer(inv -> {
                auditedInsideTransaction.set(inTransaction.get());
                return Mono.empty();
            });

            // Act
            var result = remover.remove(credential, USER_ID, Map.of());

            // Assert
            StepVerifier.create(result).verifyComplete();
            org.assertj.core.api.Assertions.assertThat(auditedInsideTransaction).isTrue();
        }

        @Test
        @DisplayName("an audit failure rolls the deletion back instead of leaving it unrecorded")
        void remove_auditFails_propagatesTheErrorSoTheTransactionRollsBack() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
            when(auditService.record(any(), any(), any(), any(), any())).thenReturn(Mono.error(new IllegalStateException("audit down")));

            // Act
            var result = remover.remove(credential, USER_ID, Map.of());

            // Assert
            StepVerifier.create(result).expectError(IllegalStateException.class).verify();
        }

        @Test
        @DisplayName("deletes the key material before the row, in one transaction")
        void remove_credential_deletesItsKeyMaterialBeforeTheRowInOneTransaction() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);

            // Act
            var result = remover.remove(credential, USER_ID, Map.of());

            // Assert
            StepVerifier.create(result).verifyComplete();
            var order = inOrder(transactionRunner, holderKeyMaterial, credentialRepository);
            order.verify(transactionRunner).inTransaction(any());
            order.verify(holderKeyMaterial).delete(credential);
            order.verify(credentialRepository).deleteById(CREDENTIAL_ID);
        }

        @Test
        @DisplayName("a failing key material deletion keeps the row and leaves no audit entry")
        void remove_keyMaterialDeletionFails_doesNotDeleteTheCredentialNorAudit() {
            // Arrange
            var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
            when(holderKeyMaterial.delete(credential)).thenReturn(Mono.error(new IllegalStateException("db down")));

            // Act
            var result = remover.remove(credential, USER_ID, Map.of());

            // Assert
            StepVerifier.create(result).expectError(IllegalStateException.class).verify();
            verify(credentialRepository, never()).deleteById(any());
            verifyNoInteractions(auditService);
        }
    }
}
