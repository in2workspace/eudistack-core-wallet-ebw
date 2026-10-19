package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.exception.CredentialNotFoundException;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.credential;
import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.response;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link GetCredentialWorkflow} — owner-scoped lookup of a single credential.
 */
@ExtendWith(MockitoExtension.class)
class GetCredentialWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID CREDENTIAL_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;

    private GetCredentialWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new GetCredentialWorkflow(credentialRepository, credentialService);
    }

    @Test
    void getCredential_ownedCredential_returnsItsVerifiableCredentialView() {
        // Arrange
        var credential = credential(CREDENTIAL_ID, USER_ID, CredentialStatus.VALID);
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.just(credential));
        when(credentialService.toVerifiableCredential(credential)).thenReturn(response(CREDENTIAL_ID.toString()));

        // Act
        var result = workflow.getCredential(USER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result.map(vc -> vc.id()))
                .expectNext(CREDENTIAL_ID.toString())
                .verifyComplete();
    }

    @Test
    void getCredential_missingOrNotOwned_failsWithCredentialNotFound() {
        // Arrange
        when(credentialRepository.findByIdAndUserId(CREDENTIAL_ID, USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.getCredential(USER_ID, CREDENTIAL_ID);

        // Assert
        StepVerifier.create(result)
                .expectError(CredentialNotFoundException.class)
                .verify();
        verifyNoInteractions(credentialService);
    }
}
