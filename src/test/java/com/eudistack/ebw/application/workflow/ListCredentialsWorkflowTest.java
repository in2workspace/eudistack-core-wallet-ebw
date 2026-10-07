package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.util.UUID;

import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.credential;
import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.response;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ListCredentialsWorkflow} — filter normalisation and the unfiltered / filtered lookups.
 */
@ExtendWith(MockitoExtension.class)
class ListCredentialsWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;

    private ListCredentialsWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ListCredentialsWorkflow(credentialRepository, credentialService);
    }

    @Test
    void listCredentials_noFilters_listsEveryCredentialOfTheUser() {
        // Arrange
        var first = credential(UUID.randomUUID(), USER_ID, CredentialStatus.VALID);
        var second = credential(UUID.randomUUID(), USER_ID, CredentialStatus.REVOKED);
        when(credentialRepository.findAllByUserId(USER_ID)).thenReturn(Flux.just(first, second));
        when(credentialService.toVerifiableCredential(first)).thenReturn(response("first"));
        when(credentialService.toVerifiableCredential(second)).thenReturn(response("second"));

        // Act
        var result = workflow.listCredentials(USER_ID, null, null, null);

        // Assert
        StepVerifier.create(result.map(vc -> vc.id()).sort())
                .expectNext("first", "second")
                .verifyComplete();
        verify(credentialRepository, never()).findAllByUserIdAndFilters(any(), any(), any(), any());
    }

    @Test
    void listCredentials_blankFilters_areTreatedAsAbsent() {
        // Arrange
        when(credentialRepository.findAllByUserId(USER_ID)).thenReturn(Flux.empty());

        // Act
        var result = workflow.listCredentials(USER_ID, "  ", "", " ");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(credentialRepository).findAllByUserId(USER_ID);
    }

    @Test
    void listCredentials_paddedFilters_areStrippedAndPassedToTheFilteredQuery() {
        // Arrange
        var credential = credential(UUID.randomUUID(), USER_ID, CredentialStatus.VALID);
        when(credentialRepository.findAllByUserIdAndFilters(USER_ID, CredentialStatus.VALID, "cfg-1", "https://issuer"))
                .thenReturn(Flux.just(credential));
        when(credentialService.toVerifiableCredential(credential)).thenReturn(response("only"));

        // Act
        var result = workflow.listCredentials(USER_ID, " VALID ", " cfg-1 ", " https://issuer ");

        // Assert
        StepVerifier.create(result.map(vc -> vc.id()))
                .expectNext("only")
                .verifyComplete();
    }

    @Test
    void listCredentials_onlyIssuerFilter_queriesWithoutStatus() {
        // Arrange
        when(credentialRepository.findAllByUserIdAndFilters(USER_ID, null, null, "https://issuer"))
                .thenReturn(Flux.empty());

        // Act
        var result = workflow.listCredentials(USER_ID, null, null, "https://issuer");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(credentialRepository).findAllByUserIdAndFilters(USER_ID, null, null, "https://issuer");
    }

    @Test
    void listCredentials_unknownStatusFilter_failsWithIllegalArgument() {
        // Act
        var result = workflow.listCredentials(USER_ID, "ARCHIVED", null, null);

        // Assert
        StepVerifier.create(result)
                .expectErrorMatches(e -> e instanceof IllegalArgumentException
                        && e.getMessage().equals("Invalid status filter: ARCHIVED"))
                .verify();
        verifyNoInteractions(credentialRepository, credentialService);
    }

    @Test
    void listCredentials_repositoryFails_propagatesTheError() {
        // Arrange
        when(credentialRepository.findAllByUserId(USER_ID)).thenReturn(Flux.error(new IllegalStateException("db down")));

        // Act
        var result = workflow.listCredentials(USER_ID, null, null, null);

        // Assert
        StepVerifier.create(result)
                .expectErrorMessage("db down")
                .verify();
    }
}
