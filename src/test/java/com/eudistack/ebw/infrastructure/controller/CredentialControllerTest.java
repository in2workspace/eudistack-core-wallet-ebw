package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.DeleteCredentialWorkflow;
import com.eudistack.ebw.application.workflow.GetCredentialWorkflow;
import com.eudistack.ebw.application.workflow.ListCredentialsWorkflow;
import com.eudistack.ebw.application.workflow.StoreCredentialWorkflow;
import com.eudistack.ebw.application.workflow.UpdateCredentialStatusWorkflow;
import com.eudistack.ebw.domain.model.CredentialFormat;
import com.eudistack.ebw.domain.model.CredentialStatus;
import com.eudistack.ebw.domain.model.WalletCredential;
import com.eudistack.ebw.infrastructure.controller.dto.StoreCredentialRequest;
import com.eudistack.ebw.infrastructure.controller.dto.UpdateStatusRequest;
import com.eudistack.ebw.infrastructure.controller.dto.VerifiableCredentialResponse;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CredentialController} — every endpoint is scoped to the caller's user id and maps the
 * workflow result to its response DTO.
 */
@ExtendWith(MockitoExtension.class)
class CredentialControllerTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private StoreCredentialWorkflow storeCredentialWorkflow;
    @Mock private ListCredentialsWorkflow listCredentialsWorkflow;
    @Mock private GetCredentialWorkflow getCredentialWorkflow;
    @Mock private UpdateCredentialStatusWorkflow updateCredentialStatusWorkflow;
    @Mock private DeleteCredentialWorkflow deleteCredentialWorkflow;

    private CredentialController controller;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        controller = new CredentialController(storeCredentialWorkflow, listCredentialsWorkflow, getCredentialWorkflow,
                updateCredentialStatusWorkflow, deleteCredentialWorkflow);
        auth = new JwtAuthenticationToken(USER_ID, "holder@example.com", List.of());
    }

    @Test
    void store_validRequest_returns201WithLocationAndDetail() {
        // Arrange
        var credential = credential(CredentialStatus.VALID);
        var metadata = Map.<String, Object>of("credential_issuer", "https://issuer");
        when(storeCredentialWorkflow.storeCredential(USER_ID, "raw", "dc+sd-jwt", "cfg-1", "kid-1", metadata, null))
                .thenReturn(Mono.just(credential));

        // Act
        var result = controller.store(new StoreCredentialRequest("raw", "dc+sd-jwt", "cfg-1", "kid-1", metadata), auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
                    assertThat(response.getHeaders().getLocation())
                            .isEqualTo(URI.create("/api/v1/credentials/" + credential.getId()));
                    assertThat(response.getBody().id()).isEqualTo(credential.getId());
                    assertThat(response.getBody().format()).isEqualTo("dc+sd-jwt");
                    assertThat(response.getBody().status()).isEqualTo("VALID");
                    assertThat(response.getBody().holderKeyId()).isEqualTo("hk-1");
                })
                .verifyComplete();
    }

    @Test
    void list_withFilters_collectsTheWorkflowResults() {
        // Arrange
        var vc = new VerifiableCredentialResponse(List.of(), "id-1", List.of("VerifiableCredential"), "VALID",
                null, null, null, null, null, Map.of(), null, null, "dc+sd-jwt", null, null);
        when(listCredentialsWorkflow.listCredentials(USER_ID, "VALID", "cfg-1", "https://issuer"))
                .thenReturn(Flux.just(vc));

        // Act
        var result = controller.list("VALID", "cfg-1", "https://issuer", auth);

        // Assert
        StepVerifier.create(result).expectNext(List.of(vc)).verifyComplete();
    }

    @Test
    void getById_ownedCredential_returnsTheWorkflowView() {
        // Arrange
        var id = UUID.randomUUID();
        var vc = new VerifiableCredentialResponse(List.of(), id.toString(), List.of(), "VALID",
                null, null, null, null, null, Map.of(), null, null, "jwt_vc_json", null, null);
        when(getCredentialWorkflow.getCredential(USER_ID, id)).thenReturn(Mono.just(vc));

        // Act
        var result = controller.getById(id, auth);

        // Assert
        StepVerifier.create(result).expectNext(vc).verifyComplete();
    }

    @Test
    void updateStatus_newStatus_returnsTheUpdatedDetail() {
        // Arrange
        var credential = credential(CredentialStatus.REVOKED);
        when(updateCredentialStatusWorkflow.updateStatus(USER_ID, credential.getId(), "REVOKED"))
                .thenReturn(Mono.just(credential));

        // Act
        var result = controller.updateStatus(credential.getId(), new UpdateStatusRequest("REVOKED"), auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(detail -> assertThat(detail.status()).isEqualTo("REVOKED"))
                .verifyComplete();
    }

    @Test
    void delete_ownedCredential_delegatesToTheWorkflow() {
        // Arrange
        var id = UUID.randomUUID();
        when(deleteCredentialWorkflow.deleteCredential(USER_ID, id)).thenReturn(Mono.empty());

        // Act
        var result = controller.delete(id, auth);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(deleteCredentialWorkflow).deleteCredential(USER_ID, id);
    }

    private static WalletCredential credential(CredentialStatus status) {
        var now = Instant.now();
        return new WalletCredential(UUID.randomUUID(), USER_ID, "raw", CredentialFormat.DC_SD_JWT, "cfg-1", "kid-1",
                "LEARCredentialEmployee", "urn:vct", "https://issuer", "did:sub", now, null, status,
                Map.of(), "hk-1", now, now);
    }
}
