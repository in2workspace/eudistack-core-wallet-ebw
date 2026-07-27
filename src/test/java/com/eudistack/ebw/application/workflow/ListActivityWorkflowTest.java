package com.eudistack.ebw.application.workflow;

import com.eudistack.ebw.domain.model.ActivityType;
import com.eudistack.ebw.domain.model.WalletActivity;
import com.eudistack.ebw.domain.repository.WalletActivityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ListActivityWorkflow} — holder-scoped listing capped at 200 entries (EUD-141).
 */
@ExtendWith(MockitoExtension.class)
class ListActivityWorkflowTest {

    private static final UUID USER_ID = UUID.randomUUID();
    private static final int MAX_ENTRIES = 200;

    @Mock private WalletActivityRepository activityRepository;

    private ListActivityWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new ListActivityWorkflow(activityRepository);
    }

    @Test
    void listActivity_delegatesToRepositoryWithCapOf200() {
        when(activityRepository.findRecentByUserId(USER_ID, MAX_ENTRIES)).thenReturn(Flux.empty());

        StepVerifier.create(workflow.listActivity(USER_ID)).verifyComplete();

        verify(activityRepository).findRecentByUserId(USER_ID, MAX_ENTRIES);
    }

    @Test
    void listActivity_holderWithNoActivity_returnsEmptyFluxWithoutError() {
        when(activityRepository.findRecentByUserId(USER_ID, MAX_ENTRIES)).thenReturn(Flux.empty());

        StepVerifier.create(workflow.listActivity(USER_ID))
                .expectNextCount(0)
                .verifyComplete();
    }

    @Test
    void listActivity_repositoryReturnsEntries_emitsThemAsIs() {
        var first = new WalletActivity(UUID.randomUUID(), USER_ID, ActivityType.ISSUED,
                "cred-1", "issuer-1", null, null, Instant.now());
        var second = new WalletActivity(UUID.randomUUID(), USER_ID, ActivityType.PRESENTED,
                "cred-2", "verifier-1", null, null, Instant.now());
        when(activityRepository.findRecentByUserId(USER_ID, MAX_ENTRIES)).thenReturn(Flux.just(first, second));

        StepVerifier.create(workflow.listActivity(USER_ID))
                .expectNext(first)
                .expectNext(second)
                .verifyComplete();
    }
}
