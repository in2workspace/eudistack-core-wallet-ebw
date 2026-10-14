package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.DeletePasskeyWorkflow;
import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow;
import com.eudistack.ebw.application.workflow.RevokePasskeySessionsWorkflow;
import com.eudistack.ebw.application.workflow.UpdatePasskeyWorkflow;
import com.eudistack.ebw.infrastructure.controller.dto.UpdatePasskeyRequest;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the device management endpoints of {@link PasskeyController}. Plain direct
 * method calls rather than {@code WebTestClient}; this class only proves the controller wires
 * arguments to the right workflow.
 */
class PasskeyControllerTest {

    private ListPasskeysWorkflow listPasskeysWorkflow;
    private UpdatePasskeyWorkflow updatePasskeyWorkflow;
    private DeletePasskeyWorkflow deletePasskeyWorkflow;
    private RevokePasskeySessionsWorkflow revokePasskeySessionsWorkflow;
    private PasskeyController controller;

    private UUID userId;
    private JwtAuthenticationToken auth;

    @BeforeEach
    void setUp() {
        listPasskeysWorkflow = mock(ListPasskeysWorkflow.class);
        updatePasskeyWorkflow = mock(UpdatePasskeyWorkflow.class);
        deletePasskeyWorkflow = mock(DeletePasskeyWorkflow.class);
        revokePasskeySessionsWorkflow = mock(RevokePasskeySessionsWorkflow.class);
        controller = new PasskeyController(
                listPasskeysWorkflow,
                updatePasskeyWorkflow,
                deletePasskeyWorkflow,
                revokePasskeySessionsWorkflow);

        userId = UUID.randomUUID();
        auth = new JwtAuthenticationToken(userId, "user@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of());
    }

    @Test
    void list_passkeysWithSessions_mapsActiveSessionCounts() {
        // Arrange
        var passkey = TestPasskeys.create(userId, "cred-1", "My PC", "ua");
        when(listPasskeysWorkflow.listPasskeys(userId))
                .thenReturn(Flux.just(new ListPasskeysWorkflow.PasskeyWithSessions(passkey, 2)));

        // Act
        var result = controller.list(auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(list -> {
                    assertThat(list).hasSize(1);
                    assertThat(list.get(0).id()).isEqualTo(passkey.getId());
                    assertThat(list.get(0).activeSessions()).isEqualTo(2);
                })
                .verifyComplete();
    }

    @Test
    void update_newDisplayName_returnsTheRenamedPasskey() {
        // Arrange
        var passkey = TestPasskeys.create(userId, "cred-1", "Renamed", "ua");
        when(updatePasskeyWorkflow.updatePasskey(userId, passkey.getId(), "Renamed")).thenReturn(Mono.just(passkey));

        // Act
        var result = controller.update(passkey.getId(), new UpdatePasskeyRequest("Renamed"), auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.displayName()).isEqualTo("Renamed");
                    assertThat(response.activeSessions()).isZero();
                })
                .verifyComplete();
    }

    @Test
    void delete_delegatesToTheWorkflowWithTheCallersUserId() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        when(deletePasskeyWorkflow.deletePasskey(userId, passkeyId)).thenReturn(Mono.empty());

        // Act
        var result = controller.delete(passkeyId, auth);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(deletePasskeyWorkflow).deletePasskey(userId, passkeyId);
    }

    @Test
    void revokeSessions_delegatesToTheWorkflowWithTheCallersUserId() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        when(revokePasskeySessionsWorkflow.revokeSessions(userId, passkeyId)).thenReturn(Mono.empty());

        // Act
        var result = controller.revokeSessions(passkeyId, auth);

        // Assert
        StepVerifier.create(result).verifyComplete();
        verify(revokePasskeySessionsWorkflow).revokeSessions(userId, passkeyId);
    }
}
