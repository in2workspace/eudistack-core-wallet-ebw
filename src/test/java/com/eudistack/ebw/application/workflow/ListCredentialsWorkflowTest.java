package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.repository.WalletCredentialRepository;
import com.eudistack.ebw.domain.service.CredentialService;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.credential;
import static com.eudistack.ebw.application.workflow.CredentialWorkflowFixtures.response;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ListCredentialsWorkflow} — filter normalisation and the unfiltered / filtered lookups.
 */
@ExtendWith(MockitoExtension.class)
class ListCredentialsWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID PASSKEY_ID = UUID.randomUUID();

    @Mock private WalletCredentialRepository credentialRepository;
    @Mock private CredentialService credentialService;
    @Mock private PasskeyCustodyPolicy custodyPolicy;

    private ListCredentialsWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ListCredentialsWorkflow(credentialRepository, credentialService, custodyPolicy);
        lenient().when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(false));
    }

    @Test
    void listCredentials_passkeyCustody_listsUnboundAndThoseOfTheSessionPasskey() {
        // Arrange — EUD-11 AC-04, AC-05, AC-10, AC-11
        var unbound = credential(USER_ID, false, null);
        var ofSessionPasskey = credential(USER_ID, true, PASSKEY_ID);
        var ofOtherPasskey = credential(USER_ID, true, UUID.randomUUID());
        var ofDeletedPasskey = credential(USER_ID, true, null);
        when(custodyPolicy.isPasskeyCustody()).thenReturn(Mono.just(true));
        when(credentialRepository.findAllByUserId(USER_ID))
                .thenReturn(Flux.just(unbound, ofSessionPasskey, ofOtherPasskey, ofDeletedPasskey));
        when(credentialService.toVerifiableCredential(unbound)).thenReturn(response("unbound"));
        when(credentialService.toVerifiableCredential(ofSessionPasskey)).thenReturn(response("mine"));

        // Act
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, null, null, null);

        // Assert
        StepVerifier.create(result.map(VerifiableCredentialResponse::id).collectList())
                .assertNext(ids -> assertThat(ids).containsExactlyInAnyOrder("unbound", "mine"))
                .verifyComplete();
        verify(credentialService, never()).toVerifiableCredential(ofOtherPasskey);
        verify(credentialService, never()).toVerifiableCredential(ofDeletedPasskey);
    }

    @Test
    void listCredentials_serverCustody_listsBoundCredentialsOfAnyPasskey() {
        // Arrange — EUD-11 AC-01: other tenants are unchanged
        var ofOtherPasskey = credential(USER_ID, true, UUID.randomUUID());
        when(credentialRepository.findAllByUserId(USER_ID)).thenReturn(Flux.just(ofOtherPasskey));
        when(credentialService.toVerifiableCredential(ofOtherPasskey)).thenReturn(response("other"));

        // Act + Assert
        StepVerifier.create(workflow.listCredentials(USER_ID, PASSKEY_ID, null, null, null))
                .expectNextCount(1)
                .verifyComplete();
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
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, null, null, null);

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
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, "  ", "", " ");

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
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, " VALID ", " cfg-1 ", " https://issuer ");

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
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, null, null, "https://issuer");

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(credentialRepository).findAllByUserIdAndFilters(USER_ID, null, null, "https://issuer");
    }

    @Test
    void listCredentials_unknownStatusFilter_failsWithIllegalArgument() {
        // Act
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, "ARCHIVED", null, null);

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
        var result = workflow.listCredentials(USER_ID, PASSKEY_ID, null, null, null);

        // Assert
        StepVerifier.create(result)
                .expectErrorMessage("db down")
                .verify();
    }
}
