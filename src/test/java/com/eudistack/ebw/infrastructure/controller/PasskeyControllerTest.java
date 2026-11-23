package com.eudistack.ebw.infrastructure.controller;

import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow;
import com.eudistack.ebw.infrastructure.security.JwtAuthenticationToken;
import com.eudistack.ebw.support.TestPasskeys;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PasskeyController}: the only passkey route left is the list for the Signal API
 * (EUD-15 AD-4), with the identifiers and dates of each passkey.
 */
class PasskeyControllerTest {

    @Test
    void list_passkeysOfTheAccount_mapsIdentifiersAndDates() {
        // Arrange
        var workflow = mock(ListPasskeysWorkflow.class);
        var controller = new PasskeyController(workflow);
        var userId = UUID.randomUUID();
        var auth = new JwtAuthenticationToken(userId, "user@example.com", UUID.randomUUID(), UUID.randomUUID(),
                List.of());
        var passkey = TestPasskeys.create(userId, "cred-1", "My PC", "ua");
        when(workflow.listPasskeys(userId)).thenReturn(Flux.just(passkey));

        // Act
        var result = controller.list(auth);

        // Assert
        StepVerifier.create(result)
                .assertNext(list -> {
                    assertThat(list).hasSize(1);
                    assertThat(list.get(0).id()).isEqualTo(passkey.getId());
                    assertThat(list.get(0).credentialId()).isEqualTo("cred-1");
                    assertThat(list.get(0).createdAt()).isEqualTo(passkey.getCreatedAt());
                })
                .verifyComplete();
    }
}
