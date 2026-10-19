package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.application.workflow.ListPasskeysWorkflow.PasskeyWithSessions;
import com.eudistack.ebw.domain.model.UserPasskey;
import com.eudistack.ebw.domain.repository.RefreshTokenRepository;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ListPasskeysWorkflow} — each passkey paired with its active session count.
 */
@ExtendWith(MockitoExtension.class)
class ListPasskeysWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private UserPasskeyRepository passkeyRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private ListPasskeysWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ListPasskeysWorkflow(passkeyRepository, refreshTokenRepository);
    }

    @Test
    void listPasskeys_passkeysWithAndWithoutSessions_pairsEachWithItsCountKeepingOrder() {
        // Arrange
        var laptop = UserPasskey.create(USER_ID, "cred-1", "Laptop", "ua");
        var phone = UserPasskey.create(USER_ID, "cred-2", "Phone", "ua");
        when(passkeyRepository.findByUserId(USER_ID)).thenReturn(Flux.just(laptop, phone));
        when(refreshTokenRepository.countActiveByPasskeyId(laptop.getId())).thenReturn(Mono.just(3L));
        when(refreshTokenRepository.countActiveByPasskeyId(phone.getId())).thenReturn(Mono.empty());

        // Act
        var result = workflow.listPasskeys(USER_ID);

        // Assert
        StepVerifier.create(result)
                .expectNext(new PasskeyWithSessions(laptop, 3L))
                .expectNext(new PasskeyWithSessions(phone, 0L))
                .verifyComplete();
    }

    @Test
    void listPasskeys_userWithoutPasskeys_returnsEmpty() {
        // Arrange
        when(passkeyRepository.findByUserId(USER_ID)).thenReturn(Flux.empty());

        // Act
        var result = workflow.listPasskeys(USER_ID);

        // Assert
        StepVerifier.create(result).verifyComplete();
    }
}
