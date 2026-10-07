package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.model.exception.PasskeyNotFoundException;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UpdatePasskeyWorkflow} — owner-scoped rename of a passkey.
 */
@ExtendWith(MockitoExtension.class)
class UpdatePasskeyWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private UserPasskeyRepository passkeyRepository;

    private UpdatePasskeyWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new UpdatePasskeyWorkflow(passkeyRepository);
    }

    @Test
    void updatePasskey_ownedPasskey_savesTheNewDisplayName() {
        // Arrange
        var passkey = UserPasskey.create(USER_ID, "cred-1", "Old name", "ua");
        when(passkeyRepository.findByIdAndUserId(passkey.getId(), USER_ID)).thenReturn(Mono.just(passkey));
        when(passkeyRepository.save(passkey)).thenReturn(Mono.just(passkey));

        // Act
        var result = workflow.updatePasskey(USER_ID, passkey.getId(), "New name");

        // Assert
        StepVerifier.create(result)
                .assertNext(saved -> assertThat(saved.getDisplayName()).isEqualTo("New name"))
                .verifyComplete();
    }

    @Test
    void updatePasskey_missingOrNotOwned_failsWithPasskeyNotFound() {
        // Arrange
        var passkeyId = UUID.randomUUID();
        when(passkeyRepository.findByIdAndUserId(passkeyId, USER_ID)).thenReturn(Mono.empty());

        // Act
        var result = workflow.updatePasskey(USER_ID, passkeyId, "New name");

        // Assert
        StepVerifier.create(result).expectError(PasskeyNotFoundException.class).verify();
        verify(passkeyRepository, never()).save(any());
    }
}
