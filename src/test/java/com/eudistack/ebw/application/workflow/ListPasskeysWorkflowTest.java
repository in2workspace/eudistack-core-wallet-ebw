package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.support.TestPasskeys;
import com.eudistack.ebw.domain.repository.UserPasskeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.Mockito.when;

/** Unit tests for {@link ListPasskeysWorkflow}: the passkeys of the account, without session counts (EUD-15 AD-4). */
@ExtendWith(MockitoExtension.class)
class ListPasskeysWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();

    @Mock private UserPasskeyRepository passkeyRepository;

    private ListPasskeysWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ListPasskeysWorkflow(passkeyRepository);
    }

    @Test
    void listPasskeys_accountWithPasskeys_emitsThemInOrder() {
        // Arrange
        var laptop = TestPasskeys.create(USER_ID, "cred-1", "Laptop", "ua");
        var phone = TestPasskeys.create(USER_ID, "cred-2", "Phone", "ua");
        when(passkeyRepository.findByUserId(USER_ID)).thenReturn(Flux.just(laptop, phone));

        // Act
        var result = workflow.listPasskeys(USER_ID);

        // Assert
        StepVerifier.create(result).expectNext(laptop, phone).verifyComplete();
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
